import logging
import traceback
import uuid
from time import sleep

import celery
from celery import chain, chord, signals
from celery.app import trace
from celery.result import AsyncResult, allow_join_result

from secator.definitions import (CELERY_BROKER_URL, CELERY_DATA_FOLDER,
								 CELERY_RESULT_BACKEND)
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.runners._helpers import run_extractors
from secator.utils import (TaskError, deduplicate, discover_external_tasks,
						   discover_internal_tasks, flatten)

logger = logging.getLogger(__name__)

trace.LOG_SUCCESS = """\
Task %(name)s[%(id)s] succeeded in %(runtime)ss\
"""
COMMANDS = discover_internal_tasks() + discover_external_tasks()

app = celery.Celery(__name__)
app.conf.update({
	# Broker config
	'broker_url': CELERY_BROKER_URL,
	'broker_transport_options': {
		'data_folder_in': CELERY_DATA_FOLDER,
		'data_folder_out': CELERY_DATA_FOLDER,
	},
	'broker_connection_retry_on_startup': True,

	# Serialization / compression
	'accept_content': ['application/x-python-serialize'],
	'task_compression': 'gzip',
	'task_serializer': 'pickle',
	'result_serializer': 'pickle',

	# Backend config
	'result_backend': CELERY_RESULT_BACKEND,
	'result_extended': True,

	# Celery config
	'task_eager_propagates': False
})


@signals.setup_logging.connect
def void(*args, **kwargs):
	"""Override celery's logging setup to prevent it from altering our settings.
	github.com/celery/celery/issues/1867
	"""
	pass


def revoke_task(task_id):
	console.print(f'Revoking task {task_id}')
	return app.control.revoke(task_id, terminate=True, signal='SIGKILL')


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
			opts['chunked'] = True
		sig = task_cls.s(chunk, **opts)
		sigs.append(sig)

	# Build Celery workflow
	workflow = chain(
		forward_results.s(results),
		chord(
			tuple(sigs),
			forward_results.s(),
		)
	)
	return workflow


@app.task(bind=True)
def run_task(self, args=[], kwargs={}):
	if 'context' not in kwargs:
		kwargs['context'] = {}
	kwargs['context']['celery_id'] = self.request.id
	task = Task(*args, **kwargs)
	task.run()


@app.task(bind=True)
def run_workflow(self, args=[], kwargs={}):
	if 'context' not in kwargs:
		kwargs['context'] = {}
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
	chunk_count = opts.get('chunk_count')
	description = opts.get('description')
	sync = opts.get('sync', True)

	# Set Celery request id in context
	context = opts.get('context', {})
	context['celery_id'] = self.request.id
	opts['context'] = context

	# Update task state in backend
	count = 0
	task_results = []
	task_state = 'RUNNING'
	task = None
	state = {
		'state': task_state,
		'meta': {
			'name': name,
			'results': [],
			'chunk': chunk,
			'chunk_count': chunk_count,
			'count': count,
			'description': description
		}
	}
	self.update_state(**state)

	try:
		# Flatten + dedupe results
		results = flatten(results)
		results = deduplicate(results, attr='_uuid')

		# Get expanded targets
		if not chunk:
			targets, opts = run_extractors(results, opts, targets)
			if not targets:
				raise ValueError(f'{name}: No targets were specified as input.')

		# Get task class
		task_cls = Task.get_task_class(name)

		# If task doesn't support multiple targets, or if the number of targets is too big, split into multiple tasks
		multiple_targets = isinstance(targets, list) and len(targets) > 1
		single_target_only = multiple_targets and task_cls.file_flag is None
		break_size_threshold = multiple_targets and task_cls.input_chunk_size and len(targets) > task_cls.input_chunk_size

		if single_target_only or (not sync and break_size_threshold):
			chunk_size = 1 if single_target_only else task_cls.input_chunk_size
			workflow = break_task(
				task_cls,
				opts,
				targets,
				results=results,
				chunk_size=chunk_size)

			result = workflow.apply() if sync else workflow()
			# self.update_state(**state)

			# TODO: here we want to update the parent task state with the
			# children info as they are executing, to update the run count etc...
			# but we cannot call `self.update_state` after the previous line
			# for (once again) some obscure Celery reason, thus preventing us to
			# do this ... Try to refactor this in a much cleaner way by using a
			# dispatcher task, maybe it could work ...
			# if not sync:
			# 	from secator.runners._base import Runner
			# 	from secator.runners._helpers import get_task_ids
			# 	ntasks = len(targets) // chunk_size
			# 	state['meta']['chunk_info'] = f'0/{ntasks}'
			# 	state['meta']['error'] = None
			# 	print(state)
			# 	subtasks = {}
			# 	task_ids = []
			# 	get_task_ids(result, ids=task_ids)
			# 	for info in Runner.get_live_results(result):
			# 		print(info)
			# 		subtasks[info['id']] = info
			# 		ready_count = sum(subtasks.get(id, {}).get('count', 0) for id in task_ids)
			# 		error = '\n\n'.join([subtasks.get(id, {}).get('error') or '' for id in task_ids])
			# 		print(ready_count)
			# 		print(error)
			# 		state['meta']['chunk_info'] = f'{ready_count}/{chunk_size}'
			# 		state['meta']['error'] = error.strip()
			# 		self.update_state(**state)
			# 		sleep(1)
			with allow_join_result():
				task_results = result.get()
				results.extend(task_results)
				state['state'] = 'SUCCESS'
				state['meta']['results'] = results
				state['meta']['count'] = len(task_results)
				self.update_state(**state)
				return results

		# If list with 1 element
		if isinstance(targets, list) and len(targets) == 1:
			targets = targets[0]

		# Run task
		task = task_cls(targets, **opts)
		for item in task:
			result_uuid = str(uuid.uuid4())
			item._uuid = result_uuid
			task_results.append(item)
			results.append(item)
			count += 1
			state['meta']['task_results'] = task_results
			state['meta']['results'] = results
			state['meta']['count'] = len(task_results)
			self.update_state(**state)

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
		state['state'] = 'SUCCESS'
		state['meta']['results'] = results
		state['meta']['task_results'] = task_results

		# Handle task failure
		if task_state == 'FAILURE':
			exc_str = ' '.join(traceback.format_exception(
				task_exc,
				value=task_exc,
				tb=task_exc.__traceback__))
			state['meta']['error'] = exc_str
			if task:
				task._print(exc_str, color='bold red')
			else:
				console.log(exc_str)

		# Update task state with final status
		self.update_state(**state)

		# If running in chunk mode, only return chunk result, not all results
		return task_results if chunk else results


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


#---------------------#
# Celery result utils #
#---------------------#

def find_root_task(result):
	while (result.parent is not None):
		result = result.parent
	return result


def poll_task(result, seen=[]):
	"""Poll Celery result tree recursively to get results live.

	TODO: function is incomplete, as it does not parse all results.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result object.
		seen (list): List of seen results (do not yield again).

	Yields:
		dict: Result.
	"""
	if result is None:
		return

	if result.children:
		for child in result.children:
			yield from poll_task(child, seen=seen)
	else:
		res = AsyncResult(result.id)
		if not res.info:
			sleep(0.1)
			yield from poll_task(result, seen=seen)

		# Task done running
		if isinstance(res.info, list):
			for item in res.info:
				if item._uuid not in seen:
					yield res.id, None, item
					seen.append(item._uuid)
			return

		# Get task partial results, remove duplicates
		results = res.info['results']
		name = res.info['name']
		for item in results:
			if item._uuid not in seen:
				yield res.id, name, item
				seen.append(item._uuid)

		# Task still running, keep polling
		if not res.ready():
			sleep(0.1)
			yield from poll_task(result, seen=seen)


def get_results(result):
	"""Get all intermediate results from Celery result object.

	Use this when running complex workflows with .si() i.e not passing results
	between tasks.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result.

	Returns:
		list: List of results.
	"""
	while not result.ready():
		continue
	results = []
	get_nested_results(result, results=results)
	return results


def get_nested_results(result, results=[]):
	"""Get results recursively from Celery result object by parsing result tree
	in reverse order. Also gets results from GroupResult children.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result object.

	Returns:
		list: List of results.
	"""
	if result is None:
		return

	if isinstance(result, celery.result.GroupResult):
		console.log(repr(result))
		get_nested_results(result.parent, results=results)
		for child in result.children:
			get_nested_results(child, results=results)

	elif isinstance(result, celery.result.AsyncResult):
		console.log(repr(result))
		res = result.get()
		console.log(f'-> Found {len(res)} results.')
		console.log(f'-> {res}')
		if res is not None:
			results.extend(res)
		get_nested_results(result.parent, results=results)


def is_celery_worker_alive():
	"""Check if a Celery worker is available."""
	"""result = app.control.broadcast('ping', reply=True, limit=1, timeout=1)
	result = bool(result)
	if result:
		console.print('Celery worker is alive !', style='bold green')
	else:
		console.print('No Celery worker alive.', style='bold red')
	return result
"""