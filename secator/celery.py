import gc
import logging
import traceback

from celery import Celery, chain, chord, signals
from celery.app import trace
from celery.result import allow_join_result
# from pyinstrument import Profiler  # TODO: make pyinstrument optional
from rich.logging import RichHandler

from secator.config import CONFIG
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.runners._helpers import run_extractors
from secator.utils import (TaskError, debug, deduplicate,
						   flatten)

# from pathlib import Path
# import memray  # TODO: conditional memray tracing

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

trace.LOG_SUCCESS = """\
Task %(name)s[%(id)s] succeeded in %(runtime)ss\
"""

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


def revoke_task(task_id):
	console.print(f'Revoking task {task_id}')
	return app.control.revoke(task_id, terminate=True, signal='SIGINT')


#--------------#
# Celery tasks #
#--------------#


def chunker(seq, size):
	return (seq[pos:pos + size] for pos in range(0, len(seq), size))


def break_task(task_cls, task_opts, targets, results=[], chunk_size=1):
	"""Break a task into multiple of the same type."""
	chunks = targets
	if chunk_size > 1:
		chunks = list(chunker(targets, chunk_size))

	# Clone opts
	opts = task_opts.copy()

	# Build signatures
	sigs = []
	for ix, chunk in enumerate(chunks):
		if len(chunks) > 0:  # add chunk to task opts for tracking chunks exec
			opts['chunk'] = ix + 1
			opts['chunk_count'] = len(chunks)
			opts['parent'] = False
		sig = task_cls.s(chunk, **opts).set(queue=task_cls.profile)
		sigs.append(sig)

	# Build Celery workflow
	workflow = chain(
		forward_results.s(results).set(queue='io'),
		chord(
			tuple(sigs),
			forward_results.s().set(queue='io'),
		)
	)
	return workflow


@app.task(bind=True)
def run_task(self, args=[], kwargs={}):
	if CONFIG.debug.level > 1:
		logger.info(f'Received task with args {args} and kwargs {kwargs}')
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	task = Task(*args, **kwargs)
	task.run()


@app.task(bind=True)
def run_workflow(self, args=[], kwargs={}):
	if CONFIG.debug.level > 1:
		logger.info(f'Received workflow with args {args} and kwargs {kwargs}')
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	workflow = Workflow(*args, **kwargs)
	workflow.run()


@app.task(bind=True)
def run_scan(self, args=[], kwargs={}):
	if CONFIG.debug.level > 1:
		logger.info(f'Received scan with args {args} and kwargs {kwargs}')
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	scan = Scan(*args, **kwargs)
	scan.run()


@app.task(bind=True)
def run_command(self, results, name, targets, opts={}):
	# profiler = Profiler(interval=0.0001)
	# profiler.start()
	chunk = opts.get('chunk')
	chunk_count = opts.get('chunk_count')
	description = opts.get('description')
	sync = opts.get('sync', True)

	# Set Celery request id in context
	context = opts.get('context', {})
	context['celery_id'] = self.request.id
	opts['context'] = context

	# Debug task
	full_name = name
	full_name += f' {chunk}/{chunk_count}' if chunk_count else ''

	# Update task state in backend
	count = 0
	msg_type = 'error'
	task_results = []
	task_state = 'RUNNING'
	task = None
	parent = True
	state = {
		'state': task_state,
		'meta': {
			'name': name,
			'progress': 0,
			'results': [],
			'chunk': chunk,
			'chunk_count': chunk_count,
			'count': count,
			'description': description
		}
	}
	self.update_state(**state)
	debug('updated', sub='celery.state', id=self.request.id, obj={full_name: 'RUNNING'}, obj_after=False, level=2)
	# profile_root = Path('/code/.profiles')
	# profile_root.mkdir(exist_ok=True)
	# profile_path = f'/code/.profiles/{self.request.id}.bin'
	# with memray.Tracker(profile_path):
	try:
		# Flatten + dedupe results
		results = flatten(results)
		results = deduplicate(results, attr='_uuid')

		# Get expanded targets
		if not chunk:
			targets, opts = run_extractors(results, opts, targets)
			if not targets:
				msg_type = 'info'
				raise TaskError(f'No targets were specified as input. Skipping. [{self.request.id}]')

		# Get task class
		task_cls = Task.get_task_class(name)

		# Get split
		multiple_targets = isinstance(targets, list) and len(targets) > 1
		single_target_only = multiple_targets and task_cls.file_flag is None
		break_size_threshold = multiple_targets and task_cls.input_chunk_size and len(targets) > task_cls.input_chunk_size

		# If task doesn't support multiple targets, or if the number of targets is too big, split into multiple tasks
		if single_target_only or (not sync and break_size_threshold):

			# Initiate main task and set context for sub-tasks
			task = task_cls(targets, parent=parent, has_children=True, **opts)
			chunk_size = 1 if single_target_only else task_cls.input_chunk_size
			debug(f'breaking task by chunks of size {chunk_size}.', id=self.request.id, sub='celery.state')
			workflow = break_task(
				task_cls,
				opts,
				targets,
				results=results,
				chunk_size=chunk_size)
			result = workflow.apply() if sync else workflow.apply_async()
			debug(
				'waiting for subtasks', sub='celery.state', id=self.request.id, obj={full_name: 'RUNNING'},
				obj_after=False, level=2)
			if not sync:
				list(task.__class__.get_live_results(result))
			with allow_join_result():
				task_results = result.get()
				results.extend(task_results)
				task_state = 'SUCCESS'
			debug(
				'all subtasks done', sub='celery.state', id=self.request.id, obj={full_name: 'RUNNING'},
		 		obj_after=False, level=2)

		# otherwise, run normally
		else:
			# If list with 1 element
			if isinstance(targets, list) and len(targets) == 1:
				targets = targets[0]

			# Run task
			task = task_cls(targets, **opts)
			for item in task:
				task_results.append(item)
				results.append(item)
				count += 1
				state['meta']['task_results'] = task_results
				state['meta']['results'] = results
				state['meta']['count'] = len(task_results)
				if item._type == 'progress':
					state['meta']['progress'] = item.percent
				self.update_state(**state)
				debug(
					'items found', sub='celery.state', id=self.request.id, obj={full_name: len(task_results)},
					obj_after=False, level=4)

			# Update task state based on task return code
			if task.return_code == 0:
				task_state = 'SUCCESS'
				task_exc = None
			else:
				task_state = 'FAILURE'
				task_exc = TaskError('\n'.join(task.errors))

	except BaseException as exc:
		task_state = 'FAILURE'
		task_exc = exc

	finally:
		# Set task state and exception
		state['state'] = 'SUCCESS'  # force task success to serialize exception
		state['meta']['results'] = results
		state['meta']['task_results'] = task_results
		state['meta']['progress'] = 100

		# Handle task failure
		if task_state == 'FAILURE':
			if isinstance(task_exc, TaskError):
				exc_str = str(task_exc)
			else:  # full traceback
				exc_str = ' '.join(traceback.format_exception(task_exc, value=task_exc, tb=task_exc.__traceback__))
			state['meta'][msg_type] = exc_str

		# Update task state with final status
		self.update_state(**state)
		debug('updated', sub='celery.state', id=self.request.id, obj={full_name: task_state}, obj_after=False, level=2)

		# Update parent task if necessary
		if task and task.has_children:
			task.log_results()
			task.run_hooks('on_end')

		# profiler.stop()
		# from pathlib import Path
		# logger.info('Stopped profiling')
		# profile_root = Path('/code/.profiles')
		# profile_root.mkdir(exist_ok=True)
		# profile_path = f'/code/.profiles/{self.request.id}.html'
		# logger.info(f'Saving profile to {profile_path}')
		# with open(profile_path, 'w', encoding='utf-8') as f_html:
		# 	f_html.write(profiler.output_html())

		# TODO: fix memory leak instead of running a garbage collector
		gc.collect()

		# If running in chunk mode, only return chunk result, not all results
		return results if parent else task_results


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
