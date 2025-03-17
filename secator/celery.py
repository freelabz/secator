import gc
import json
import logging
import os
import uuid

from time import time

from celery import Celery, chord
from celery.app import trace

from rich.logging import RichHandler
from retry import retry

from secator.celery_signals import IN_CELERY_WORKER_PROCESS, setup_handlers
from secator.config import CONFIG
from secator.output_types import Info
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.utils import (debug, deduplicate, flatten, should_update)


#---------#
# Logging #
#---------#

rich_handler = RichHandler(rich_tracebacks=True)
rich_handler.setLevel(logging.INFO)
logging.basicConfig(
	level='NOTSET',
	format="%(threadName)s:%(message)s",
	datefmt="[%X]",
	handlers=[rich_handler],
	force=True)
logging.getLogger('kombu').setLevel(logging.ERROR)
logging.getLogger('celery').setLevel(logging.INFO if CONFIG.debug.level > 6 else logging.WARNING)
logger = logging.getLogger(__name__)
trace.LOG_SUCCESS = "Task %(name)s[%(id)s] succeeded in %(runtime)ss"


#------------#
# Celery app #
#------------#

app = Celery(__name__)
app.conf.update({
	# Content types
	'accept_content': ['application/x-python-serialize', 'application/json'],

	# Broker config
	'broker_url': CONFIG.celery.broker_url,
	'broker_transport_options': json.loads(CONFIG.celery.broker_transport_options) if CONFIG.celery.broker_transport_options else {  # noqa: E501
		'data_folder_in': CONFIG.dirs.celery_data,
		'data_folder_out': CONFIG.dirs.celery_data,
		'control_folder': CONFIG.dirs.celery_data,
		'visibility_timeout': CONFIG.celery.broker_visibility_timeout,
	},
	'broker_connection_retry_on_startup': True,
	'broker_pool_limit': CONFIG.celery.broker_pool_limit,
	'broker_connection_timeout': CONFIG.celery.broker_connection_timeout,

	# Result backend config
	'result_backend': CONFIG.celery.result_backend,
	'result_expires': CONFIG.celery.result_expires,
	'result_backend_transport_options': json.loads(CONFIG.celery.result_backend_transport_options) if CONFIG.celery.result_backend_transport_options else {},  # noqa: E501
	'result_extended': True,
	'result_backend_thread_safe': True,
	'result_serializer': 'pickle',

	# Task config
	'task_acks_late': CONFIG.celery.task_acks_late,
	'task_compression': 'gzip',
	'task_create_missing_queues': True,
	'task_eager_propagates': False,
	'task_reject_on_worker_lost': CONFIG.celery.task_reject_on_worker_lost,
	'task_routes': {
		'secator.celery.run_workflow': {'queue': 'celery'},
		'secator.celery.run_scan': {'queue': 'celery'},
		'secator.celery.run_task': {'queue': 'celery'},
		'secator.celery.forward_results': {'queue': 'results'},
		'secator.hooks.mongodb.*': {'queue': 'mongodb'}
	},
	'task_store_eager_result': True,
	'task_send_sent_event': CONFIG.celery.task_send_sent_event,
	'task_serializer': 'pickle',

	# Worker config
	# 'worker_direct': True,  # TODO: consider enabling this to allow routing to specific workers
	'worker_max_tasks_per_child': CONFIG.celery.worker_max_tasks_per_child,
	# 'worker_max_memory_per_child': 100000  # TODO: consider enabling this
	'worker_pool_restarts': True,
	'worker_prefetch_multiplier': CONFIG.celery.worker_prefetch_multiplier,
	'worker_send_task_events': CONFIG.celery.worker_send_task_events
})
app.autodiscover_tasks(['secator.hooks.mongodb'], related_name=None)
if IN_CELERY_WORKER_PROCESS:
	setup_handlers()


@retry(Exception, tries=3, delay=2)
def update_state(celery_task, task, force=False):
	"""Update task state to add metadata information."""
	if not IN_CELERY_WORKER_PROCESS:
		return
	if not force and not should_update(CONFIG.runners.backend_update_frequency, task.last_updated_celery):
		return
	task.last_updated_celery = time()
	debug(
		'',
		sub='celery.state',
		id=celery_task.request.id,
		obj={task.unique_name: task.status, 'count': task.self_findings_count},
		obj_after=False,
		verbose=True
	)
	return celery_task.update_state(
		state='RUNNING',
		meta=task.celery_state
	)


def revoke_task(task_id, task_name=None):
	message = f'Revoked task {task_id}'
	if task_name:
		message += f' ({task_name})'
	app.control.revoke(task_id, terminate=True)
	console.print(Info(message=message))


#--------------#
# Celery tasks #
#--------------#


def chunker(seq, size):
	return (seq[pos:pos + size] for pos in range(0, len(seq), size))


@app.task(bind=True)
def run_task(self, args=[], kwargs={}):
	console.print(Info(message=f'Running task {self.request.id}'))
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	task = Task(*args, **kwargs)
	task.run()


@app.task(bind=True)
def run_workflow(self, args=[], kwargs={}):
	console.print(Info(message=f'Running workflow {self.request.id}'))
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	workflow = Workflow(*args, **kwargs)
	workflow.run()


@app.task(bind=True)
def run_scan(self, args=[], kwargs={}):
	console.print(Info(message=f'Running scan {self.request.id}'))
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	scan = Scan(*args, **kwargs)
	scan.run()


@app.task(bind=True)
def run_command(self, results, name, targets, opts={}):
	if IN_CELERY_WORKER_PROCESS:
		opts.update({'print_item': True, 'print_line': True, 'print_cmd': True})
		routing_key = self.request.delivery_info['routing_key']
		console.print(Info(message=f'Task "{name}" running with routing key "{routing_key}"'))

	# Flatten + dedupe + filter results
	results = forward_results(results)

	# Set Celery request id in context
	context = opts.get('context', {})
	context['celery_id'] = self.request.id
	context['worker_name'] = os.environ.get('WORKER_NAME', 'unknown')
	opts['context'] = context
	opts['results'] = results
	opts['sync'] = True

	# Initialize task
	sync = not IN_CELERY_WORKER_PROCESS
	task_cls = Task.get_task_class(name)
	task = task_cls(targets, **opts)
	task.started = True
	task.run_hooks('on_start')
	update_state(self, task, force=True)

	# Chunk task if needed
	if task.needs_chunking(sync):
		if IN_CELERY_WORKER_PROCESS:
			console.print(Info(message=f'Task {name} requires chunking, breaking into {len(targets)} tasks'))
		tasks = break_task(task, opts, results=results)
		update_state(self, task, force=True)
		return self.replace(tasks)

	# Update state live
	[update_state(self, task) for _ in task]
	update_state(self, task, force=True)

	# Garbage collection to save RAM
	gc.collect()

	return task.results


@app.task
def forward_results(results):
	if isinstance(results, list):
		for ix, item in enumerate(results):
			if isinstance(item, dict) and 'results' in item:
				results[ix] = item['results']
	elif 'results' in results:
		results = results['results']
	results = flatten(results)
	results = deduplicate(results, attr='_uuid')
	if IN_CELERY_WORKER_PROCESS:
		console.print(Info(message=f'Forwarding {len(results)} results ...'))
	return results


@app.task
def mark_runner_started(runner):
	"""Mark a runner as started and run on_start hooks.

	Args:
		runner (Runner): Secator runner instance

	Returns:
		list: Runner results
	"""
	runner.started = True
	# runner.start_time = time()
	runner.run_hooks('on_start')
	return runner.results


@app.task
def mark_runner_complete(results, runner):
	"""Mark a runner as completed and run on_end hooks.

	Args:
		results (list): Task results
		runner (Runner): Secator runner instance

	Returns:
		list: Final results
	"""
	results = forward_results(results)

	# If sync mode, don't update the runner as it's already done
	if runner.sync:
		return results

	# Run final processing
	runner.results = results
	if not runner.no_process:
		runner.mark_duplicates()
	runner.log_results()
	runner.run_hooks('on_end')
	return runner.results


#--------------#
# Celery utils #
#--------------#


def is_celery_worker_alive():
	"""Check if a Celery worker is available."""
	result = app.control.broadcast('ping', reply=True, limit=1, timeout=1)
	result = bool(result)
	if result:
		console.print(Info(message='Celery worker is available, running remotely'))
	else:
		console.print(Info(message='No Celery worker available, running locally'))
	return result


def break_task(task, task_opts, results=[]):
	"""Break a task into multiple of the same type."""
	chunks = task.inputs
	if task.input_chunk_size > 1:
		chunks = list(chunker(task.inputs, task.input_chunk_size))
	debug(
		'',
		obj={task.unique_name: 'CHUNKED', 'chunk_size': task.input_chunk_size, 'chunks': len(chunks), 'target_count': len(task.inputs)},  # noqa: E501
		obj_after=False,
		sub='celery.state',
		verbose=True
	)

	# Clone opts
	opts = task_opts.copy()

	# Build signatures
	sigs = []
	task.ids_map = {}
	for ix, chunk in enumerate(chunks):
		if not isinstance(chunk, list):
			chunk = [chunk]
		if len(chunks) > 0:  # add chunk to task opts for tracking chunks exec
			opts['chunk'] = ix + 1
			opts['chunk_count'] = len(chunks)
		task_id = str(uuid.uuid4())
		opts['has_parent'] = True
		opts['enable_duplicate_check'] = False
		opts['results'] = results
		sig = type(task).si(chunk, **opts).set(queue=type(task).profile, task_id=task_id)
		full_name = f'{task.name}_{ix + 1}'
		task.add_subtask(task_id, task.name, f'{task.name}_{ix + 1}')
		info = Info(message=f'Celery chunked task created: {task_id}', _source=full_name, _uuid=str(uuid.uuid4()))
		task.add_result(info)
		sigs.append(sig)

	# Mark main task as async since it's being chunked
	task.sync = False

	# Build Celery workflow
	workflow = chord(
		tuple(sigs),
		mark_runner_complete.s(runner=task).set(queue='results')
	)
	return workflow
