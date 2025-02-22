import gc
import json
import logging
import sys
import uuid

from time import time

from celery import Celery, chain, chord, signals
from celery.app import trace

from rich.logging import RichHandler
from retry import retry

from secator.config import CONFIG
from secator.output_types import Info, Error
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.runners._helpers import run_extractors
from secator.utils import (debug, deduplicate, flatten, should_update)

IN_CELERY_WORKER_PROCESS = sys.argv and ('secator.celery.app' in sys.argv or 'worker' in sys.argv)

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
		'secator.hooks.mongodb.tag_duplicates': {'queue': 'mongodb'}
	},
	'task_store_eager_result': True,
	# 'task_send_sent_event': True,  # TODO: consider enabling this for Flower monitoring
	'task_serializer': 'pickle',

	# Worker config
	# 'worker_direct': True,  # TODO: consider enabling this to allow routing to specific workers
	'worker_max_tasks_per_child': CONFIG.celery.worker_max_tasks_per_child,
	# 'worker_max_memory_per_child': 100000  # TODO: consider enabling this
	'worker_pool_restarts': True,
	'worker_prefetch_multiplier': CONFIG.celery.worker_prefetch_multiplier,
	# 'worker_send_task_events': True,  # TODO: consider enabling this for Flower monitoring
})
app.autodiscover_tasks(['secator.hooks.mongodb'], related_name=None)


def maybe_override_logging():
	def decorator(func):
		if CONFIG.celery.override_default_logging:
			return signals.setup_logging.connect(func)
		else:
			return func
	return decorator


@maybe_override_logging()
def void(*args, **kwargs):
	"""Override celery's logging setup to prevent it from altering our settings.
	github.com/celery/celery/issues/1867
	"""
	pass


@retry(Exception, tries=3, delay=2)
def update_state(celery_task, task, force=False):
	"""Update task state to add metadata information."""
	if task.sync:
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


def break_task(task, task_opts, targets, results=[], chunk_size=1):
	"""Break a task into multiple of the same type."""
	chunks = targets
	if chunk_size > 1:
		chunks = list(chunker(targets, chunk_size))
	debug(
		'',
		obj={task.unique_name: 'CHUNKED', 'chunk_size': chunk_size, 'chunks': len(chunks), 'target_count': len(targets)},
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
		sig = type(task).s(chunk, **opts).set(queue=type(task).profile, task_id=task_id)
		full_name = f'{task.name}_{ix + 1}'
		task.add_subtask(task_id, task.name, f'{task.name}_{ix + 1}')
		info = Info(message=f'Celery chunked task created: {task_id}', _source=full_name, _uuid=str(uuid.uuid4()))
		task.add_result(info)
		sigs.append(sig)

	# Build Celery workflow
	workflow = chain(
		forward_results.s(results).set(queue='io'),
		chord(
			tuple(sigs),
			forward_results.s().set(queue='io'),
		)
	)
	if task.sync:
		task.print_item = False
		task.results = workflow.apply().get()
	else:
		result = workflow.apply_async()
		task.celery_result = result


@app.task(bind=True)
def run_task(self, args=[], kwargs={}):
	kwargs['context']['celery_id'] = self.request.id
	task = Task(*args, **kwargs)
	task.run()


@app.task(bind=True)
def run_workflow(self, args=[], kwargs={}):
	kwargs['context']['celery_id'] = self.request.id
	workflow = Workflow(*args, **kwargs)
	workflow.run()


@app.task(bind=True)
def run_scan(self, args=[], kwargs={}):
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	scan = Scan(*args, **kwargs)
	scan.run()


@app.task(bind=True)
def run_command(self, results, name, targets, opts={}):
	chunk = opts.get('chunk')
	sync = opts.get('sync', True)

	# Set Celery request id in context
	context = opts.get('context', {})
	context['celery_id'] = self.request.id
	opts['context'] = context
	opts['print_remote_info'] = False
	opts['results'] = results

	# If we are in a Celery worker, print everything, always
	if IN_CELERY_WORKER_PROCESS:
		opts.update({
			'print_item': True,
			'print_line': True,
			'print_cmd': True
		})

	# Flatten + dedupe results
	results = flatten(results)
	results = deduplicate(results, attr='_uuid')

	# Get expanded targets
	if not chunk and results:
		targets, opts = run_extractors(results, opts, targets)
		debug('after extractors', obj={'targets': targets, 'opts': opts}, sub='celery.state')

	try:
		# Get task class
		task_cls = Task.get_task_class(name)

		# Check if chunkable
		many_targets = len(targets) > 1
		targets_over_chunk_size = task_cls.input_chunk_size and len(targets) > task_cls.input_chunk_size
		has_file_flag = task_cls.file_flag is not None
		chunk_it = (sync and many_targets and not has_file_flag) or (not sync and many_targets and targets_over_chunk_size)
		task_opts = opts.copy()
		task_opts.update({
			'print_remote_info': False,
			'has_children': chunk_it,
		})
		if chunk_it:
			task_opts['print_cmd'] = False
		task = task_cls(targets, **task_opts)
		debug(
			'',
			obj={
				f'{task.unique_name}': 'CHUNK STATUS',
				'chunk_it': chunk_it,
				'sync': task.sync,
				'many_targets': many_targets,
				'targets_over_chunk_size': targets_over_chunk_size,
			},
			obj_after=False,
			id=self.request.id,
			sub='celery.state',
			verbose=True
		)

		# Chunk task if needed
		if chunk_it:
			chunk_size = task_cls.input_chunk_size if has_file_flag else 1
			break_task(
				task,
				opts,
				targets,
				results=results,
				chunk_size=chunk_size)

		# Update state before starting
		update_state(self, task)

		# Update state for each item found
		for _ in task:
			update_state(self, task)

	except BaseException as e:
		error = Error.from_exception(e)
		error._source = task.unique_name
		error._uuid = str(uuid.uuid4())
		task.add_result(error, print=True)
		task.stop_celery_tasks()

	finally:
		update_state(self, task, force=True)
		gc.collect()
		debug('', obj={task.unique_name: task.status, 'results': task.results}, sub='celery.results', verbose=True)
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
	return results

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
