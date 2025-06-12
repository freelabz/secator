import json
import logging
import os

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
logging.getLogger('celery').setLevel(logging.DEBUG if 'celery.debug' in CONFIG.debug or 'celery.*' in CONFIG.debug else logging.WARNING)  # noqa: E501
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
	if task.no_live_updates:
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
		quiet = not CONFIG.cli.worker_command_verbose
		opts.update({
			'print_item': True,
			'print_line': True,
			'print_cmd': True,
			'print_target': True,
			'print_profiles': True,
			'quiet': quiet
		})
		routing_key = self.request.delivery_info['routing_key']
		debug(f'Task "{name}" running with routing key "{routing_key}"', sub='celery.state')

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
	chunk_it = task.needs_chunking(sync)
	task.has_children = chunk_it
	task.mark_started()
	update_state(self, task, force=True)

	# Chunk task if needed
	if chunk_it:
		if IN_CELERY_WORKER_PROCESS:
			console.print(Info(message=f'Task {name} requires chunking, breaking into {len(targets)} tasks'))
		tasks = break_task(task, opts, results=results)
		update_state(self, task, force=True)
		return self.replace(tasks)

	# Update state live
	for _ in task:
		update_state(self, task)
	update_state(self, task, force=True)

	if CONFIG.addons.mongodb.enabled:
		return [r._uuid for r in task.results]
	return task.results


@app.task
def forward_results(results):
	"""Forward results to the next task (bridge task).

	Args:
		results (list): Results to forward.

	Returns:
		list: List of uuids.
	"""
	if isinstance(results, list):
		for ix, item in enumerate(results):
			if isinstance(item, dict) and 'results' in item:
				results[ix] = item['results']
	elif 'results' in results:
		results = results['results']

	if IN_CELERY_WORKER_PROCESS:
		console.print(Info(message=f'Deduplicating {len(results)} results'))

	results = flatten(results)
	if CONFIG.addons.mongodb.enabled:
		uuids = [r._uuid for r in results if hasattr(r, '_uuid')]
		uuids.extend([r for r in results if isinstance(r, str)])
		results = list(set(uuids))
	else:
		results = deduplicate(results, attr='_uuid')

	if IN_CELERY_WORKER_PROCESS:
		console.print(Info(message=f'Forwarded {len(results)} flattened and deduplicated results'))

	return results


@app.task
def mark_runner_started(results, runner, enable_hooks=True):
	"""Mark a runner as started and run on_start hooks.

	Args:
		results (List): Previous results.
		runner (Runner): Secator runner instance.
		enable_hooks (bool): Enable hooks.

	Returns:
		list: Runner results
	"""
	if IN_CELERY_WORKER_PROCESS:
		console.print(Info(message=f'Runner {runner.unique_name} has started, running mark_started'))
	debug(f'Runner {runner.unique_name} has started, running mark_started', sub='celery')
	if results:
		results = forward_results(results)
	runner.enable_hooks = enable_hooks
	if CONFIG.addons.mongodb.enabled:
		from secator.hooks.mongodb import get_results
		results = get_results(results)
	for item in results:
		runner.add_result(item, print=False)
	runner.mark_started()
	return runner.results


@app.task
def mark_runner_completed(results, runner, enable_hooks=True):
	"""Mark a runner as completed and run on_end hooks.

	Args:
		results (list): Task results
		runner (Runner): Secator runner instance
		enable_hooks (bool): Enable hooks.

	Returns:
		list: Final results
	"""
	if IN_CELERY_WORKER_PROCESS:
		console.print(Info(message=f'Runner {runner.unique_name} has finished, running mark_completed'))
	debug(f'Runner {runner.unique_name} has finished, running mark_completed', sub='celery')
	results = forward_results(results)
	runner.enable_hooks = enable_hooks
	if CONFIG.addons.mongodb.enabled:
		from secator.hooks.mongodb import get_results
		results = get_results(results)
	for item in results:
		runner.add_result(item, print=False)
	runner.mark_completed()
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
	base_opts = task_opts.copy()

	# Build signatures
	sigs = []
	task.ids_map = {}
	for ix, chunk in enumerate(chunks):
		if not isinstance(chunk, list):
			chunk = [chunk]

		# Add chunk info to opts
		opts = base_opts.copy()
		opts.update({'chunk': ix + 1, 'chunk_count': len(chunks)})
		debug('', obj={
			task.unique_name: 'CHUNK',
			'chunk': f'{ix + 1} / {len(chunks)}',
			'target_count': len(chunk),
			'targets': chunk
		}, sub='celery.state')  # noqa: E501

		# Construct chunked signature
		opts['has_parent'] = True
		opts['enable_duplicate_check'] = False
		opts['results'] = results
		if 'targets_' in opts:
			del opts['targets_']
		sig = type(task).si(chunk, **opts)
		task_id = sig.freeze().task_id
		full_name = f'{task.name}_{ix + 1}'
		task.add_subtask(task_id, task.name, full_name)
		info = Info(message=f'Celery chunked task created: {task_id}')
		task.add_result(info)
		sigs.append(sig)

	# Mark main task as async since it's being chunked
	task.sync = False

	# Build Celery workflow
	workflow = chord(
		tuple(sigs),
		mark_runner_completed.s(runner=task).set(queue='results')
	)
	return workflow
