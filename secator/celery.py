import gc
import logging
import uuid

from celery import Celery, chain, chord, signals, states
from celery.app import trace
from celery.signals import after_task_publish, task_failure

# from pyinstrument import Profiler  # TODO: make pyinstrument optional
from rich.logging import RichHandler

from secator.config import CONFIG
from secator.output_types import Info, Error
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.runners._helpers import run_extractors
from secator.utils import (debug, deduplicate, flatten, traceback_as_string)
from secator.celery_utils import CeleryData


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
	# Worker config
	'worker_send_task_events': True,
	'worker_prefetch_multiplier': 1,
	'worker_max_tasks_per_child': 10,

	# Broker config
	'broker_url': CONFIG.celery.broker_url,
	'broker_transport_options': {
		'data_folder_in': CONFIG.dirs.celery_data,
		'data_folder_out': CONFIG.dirs.celery_data,
		'control_folder': CONFIG.dirs.celery_data,
		'visibility_timeout': CONFIG.celery.broker_visibility_timeout,
	},
	'broker_connection_retry_on_startup': True,
	'broker_pool_limit': CONFIG.celery.broker_pool_limit,
	'broker_connection_timeout': CONFIG.celery.broker_connection_timeout,

	# Backend config
	'result_backend': CONFIG.celery.result_backend,
	'result_extended': True,
	'result_backend_thread_safe': True,
	# 'result_backend_transport_options': {'master_name': 'mymaster'}, # for Redis HA backend

	# Task config
	'task_eager_propagates': False,
	'task_routes': {
		'secator.celery.run_workflow': {'queue': 'celery'},
		'secator.celery.run_scan': {'queue': 'celery'},
		'secator.celery.run_task': {'queue': 'celery'},
		'secator.hooks.mongodb.tag_duplicates': {'queue': 'mongodb'}
	},
	'task_reject_on_worker_lost': True,
	'task_acks_late': True,
	'task_create_missing_queues': True,
	'task_send_sent_event': True,

	# Serialization / compression
	'accept_content': ['application/x-python-serialize', 'application/json'],
	'task_compression': 'gzip',
	'task_serializer': 'pickle',
	'result_serializer': 'pickle'
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


@after_task_publish.connect
def handle_before_task_state(sender=None, headers=None, body=None, **kwargs):
	"""Set Celery metadata after task is published to the queue."""
	if sender == 'secator.celery.run_command':
		task_id = headers['id']
		task_name = body[0][1]
		app.backend.store_result(
			task_id,
			{
				'name': task_name,
				'full_name': task_name,
				'progress': 0
			},
			states.PENDING,
			**kwargs
		)


@task_failure.connect
def handle_task_failure(sender=None, **kwargs):
	"""Set Celery metadata when task fails."""
	if sender == 'secator.celery.run_command':
		print(kwargs)
		# task_id = headers['id']
		# task_name = body[0][1]
		# app.backend.store_result(
		# 	task_id,
		# 	{
		# 		'name': task_name,
		# 		'full_name': task_name
		# 	},
		# 	states.PENDING,
		# 	**kwargs
		# )


def revoke_task(data):
	task_id = data['id']
	full_name = data.get('full_name')
	message = f'Revoking task {task_id}'
	if full_name:
		message += f' ({full_name})'
	console.print(message)
	return app.control.revoke(task_id, terminate=True, signal='SIGINT')


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
		obj={task.unique_name: 'CHUNKED', 'chunk_size': chunk_size, 'chunks': len(chunks)},
		obj_after=False,
		sub='celery.state'
	)

	# Clone opts
	opts = task_opts.copy()

	# Build signatures
	sigs = []
	task_ids = []
	for ix, chunk in enumerate(chunks):
		if not isinstance(chunk, list):
			chunk = [chunk]
		if len(chunks) > 0:  # add chunk to task opts for tracking chunks exec
			opts['chunk'] = ix + 1
			opts['chunk_count'] = len(chunks)
			opts['parent'] = False
		sig = type(task).s(chunk, **opts).set(queue=type(task).profile)
		task_ids.append(str(sig.freeze()))
		sigs.append(sig)

	# Build Celery workflow
	workflow = chain(
		forward_results.s(results).set(queue='io'),
		chord(
			tuple(sigs),
			forward_results.s().set(queue='io'),
		)
	)
	return workflow, task_ids


@app.task(bind=True)
def run_task(self, args=[], kwargs={}):
	debug(f'Received task with args {args} and kwargs {kwargs}', sub="celery", level=2)
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	task = Task(*args, **kwargs)
	task.run()


@app.task(bind=True)
def run_workflow(self, args=[], kwargs={}):
	debug(f'Received workflow with args {args} and kwargs {kwargs}', sub="celery", level=2)
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	workflow = Workflow(*args, **kwargs)
	workflow.run()


@app.task(bind=True)
def run_scan(self, args=[], kwargs={}):
	debug(f'Received scan with args {args} and kwargs {kwargs}', sub="celery", level=2)
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	scan = Scan(*args, **kwargs)
	scan.run()


def update_state(celery_task, **state):
	debug(
		'',
		sub='celery.state',
		id=celery_task.request.id,
		obj={state['meta']['full_name']: state['meta']['state'], 'count': state['meta']['count']},
		obj_after=False
	)
	return celery_task.update_state(**state)


@app.task(bind=True)
def run_command(self, results, name, targets, opts={}):
	chunk = opts.get('chunk')

	# Set Celery request id in context
	context = opts.get('context', {})
	context['celery_id'] = self.request.id
	opts['context'] = context
	opts['print_remote_info'] = False
	opts['results'] = results

	# Set initial state
	state = {
		'state': 'RUNNING',
		'meta': {}
	}

	# Flatten + dedupe results
	results = flatten(results)
	results = deduplicate(results, attr='_uuid')

	# Get expanded targets
	if not chunk:
		targets, opts = run_extractors(results, opts, targets)

	# Get task class
	task_cls = Task.get_task_class(name)
	task = task_cls(targets, **opts)
	iterator = task

	try:
		# Check if chunkable
		many_targets = len(targets) > 1
		targets_over_chunk_size = task_cls.input_chunk_size and len(targets) > task_cls.input_chunk_size
		has_no_file_flag = task_cls.file_flag is None
		chunk_it = many_targets and (has_no_file_flag or targets_over_chunk_size) and not task.sync
		debug(
			'',
			obj={
				f'{task.unique_name}': 'CHUNK?',
				'sync': task.sync,
				'has_no_file_flag': has_no_file_flag,
				'targets_over_chunk_size': targets_over_chunk_size,
				'has_children': chunk_it
			},
			obj_after=False,
			id=task.unique_name,
			sub='celery.state'
		)
		task.has_children = chunk_it

		# Follow multiple chunked tasks
		if chunk_it:
			chunk_size = 1 if has_no_file_flag else task_cls.input_chunk_size
			workflow, task_ids = break_task(
				task,
				opts,
				targets,
				results=results,
				chunk_size=chunk_size)
			result = workflow.apply_async()
			for task_id in task_ids:
				info = Info(
					message=f'Celery chunked task created: {task_id}',
					task_id=task_id,
					_source=task.unique_name,
					_uuid=str(uuid.uuid4())
				)
				task.results.append(info)
			iterator = CeleryData.iter_results(
				result,
				print_remote_info=False
			)

		for item in iterator:
			if task.has_children:
				if item._uuid in task.uuids:
					continue
				task.results.append(item)
			state['meta'] = task.celery_state
			update_state(self, **state)

	except BaseException as exc:
		error = Error(
			message=str(exc),
			traceback=traceback_as_string(exc),
			_source=task.unique_name,
			_uuid=str(uuid.uuid4())
		)
		task.results.append(error)

	finally:
		state['meta'] = task.celery_state
		update_state(self, **state)
		gc.collect()

		# Run on_end hooks for split tasks
		if task.has_children:
			task.log_results()
			task.run_hooks('on_end')

		# If running in chunk mode, only return chunk result, not all results
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
		console.print('Celery worker is alive !', style='bold green')
	else:
		console.print('No Celery worker alive.', style='bold orange1')
	return result
