import gc
import logging
import uuid

from celery import Celery, chain, chord, signals
from celery.app import trace

# from pyinstrument import Profiler  # TODO: make pyinstrument optional
from rich.logging import RichHandler

from secator.config import CONFIG
from secator.output_types import Info, Warning, Error
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.runners._helpers import run_extractors
from secator.utils import (debug, deduplicate, flatten)


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
	'task_acks_late': False,
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


def update_state(celery_task, **state):
	"""Update task state to add metadata information."""
	debug(
		'',
		sub='celery.state',
		id=celery_task.request.id,
		obj={state['meta']['full_name']: state['meta']['state'], 'count': state['meta']['count']},
		obj_after=False
	)
	return celery_task.update_state(**state)


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
		sub='celery.state'
	)

	# Clone opts
	opts = task_opts.copy()

	# Build signatures
	sigs = []
	ids_map = {}
	for ix, chunk in enumerate(chunks):
		if not isinstance(chunk, list):
			chunk = [chunk]
		if len(chunks) > 0:  # add chunk to task opts for tracking chunks exec
			opts['chunk'] = ix + 1
			opts['chunk_count'] = len(chunks)
		task_id = str(uuid.uuid4())
		sig = type(task).s(chunk, **opts).set(queue=type(task).profile, task_id=task_id)
		ids_map[task_id] = {
			'id': task_id,
			'name': task.name,
			'full_name': f'{task.name}_{ix + 1}',
			'descr': task.config.description or '',
			'state': 'PENDING',
			'count': 0,
			'progress': 0
		}
		sigs.append(sig)

	# Build Celery workflow
	workflow = chain(
		forward_results.s(results).set(queue='io'),
		chord(
			tuple(sigs),
			forward_results.s().set(queue='io'),
		)
	)
	return workflow, ids_map


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


@app.task(bind=True)
def run_command(self, results, name, targets, opts={}):
	chunk = opts.get('chunk')
	sync = opts.get('sync')

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

	# Set task opts
	# print_opts = {
	# 	'print_cmd': True,
	# 	'print_item': True,
	# 	'print_line': True,
	# 	'print_target': True
	# }
	# opts.update(print_opts)

	try:
		# Check if chunkable
		many_targets = len(targets) > 1
		targets_over_chunk_size = task_cls.input_chunk_size and len(targets) > task_cls.input_chunk_size
		has_no_file_flag = task_cls.file_flag is None
		chunk_it = many_targets and (has_no_file_flag or targets_over_chunk_size)
		opts['has_children'] = chunk_it and not sync
		task = task_cls(targets, **opts)
		chunk_enabled = chunk_it and not task.sync
		debug(
			'',
			obj={
				f'{task.unique_name}': 'CHUNK STATUS',
				'chunk_enabled': chunk_enabled,
				'chunk_it': chunk_it,
				'sync': task.sync,
				'has_no_file_flag': has_no_file_flag,
				'targets_over_chunk_size': targets_over_chunk_size,
			},
			obj_after=False,
			id=self.request.id,
			sub='celery.state'
		)

		# Chunk task if needed
		if chunk_enabled:
			chunk_size = 1 if has_no_file_flag else task_cls.input_chunk_size
			workflow, ids_map = break_task(
				task,
				opts,
				targets,
				results=results,
				chunk_size=chunk_size)
			result = workflow.apply_async()
			task.celery_result = result
			task.celery_ids_map = ids_map
			task.celery_ids = list(ids_map.keys())
			state['meta'] = task.celery_state
			update_state(self, **state)

		# Update state for each item found
		for _ in task:
			state['meta'] = task.celery_state
			update_state(self, **state)

	except BaseException as e:
		error = Error.from_exception(e)
		error._source = task.unique_name
		error._uuid = str(uuid.uuid4())
		task._print_item(error)
		task.stop_live_tasks()
		task.results.append(error)

	finally:
		state['meta'] = task.celery_state
		update_state(self, **state)
		gc.collect()

		# Run on_end hooks for split tasks
		if task.has_children:
			task.log_results()
			task.run_hooks('on_end')

		# Return task results
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
	result = app.control.broadcast('ping', reply=True, limit=1, timeout=5)
	result = bool(result)
	if result:
		console.print(Info(message='Celery worker is alive !'))
	else:
		console.print(Warning(message='No Celery worker alive.'))
	return result
