import json
import logging
import uuid
from time import sleep

import celery
from celery import chain, chord, signals
from celery.app import trace
from celery.result import AsyncResult, allow_join_result
from celery_dyrygent.tasks import register_workflow_processor

from secsy.definitions import (CELERY_BROKER_URL, CELERY_RESULT_BACKEND,
                               TEMP_FOLDER)
from secsy.rich import console
from secsy.rich import handler as rich_handler
from secsy.runner import merge_extracted_values
from secsy.utils import (deduplicate, find_external_commands,
                         find_internal_commands, flatten)

logger = logging.getLogger(__name__)

trace.LOG_SUCCESS = """\
Task %(name)s[%(id)s] succeeded in %(runtime)ss\
"""
COMMANDS = find_internal_commands() + find_external_commands()

app = celery.Celery(__name__)
app.conf.update({
	# Configuration du broker
	'broker_url': CELERY_BROKER_URL,
	'broker_transport_options': {
		'data_folder_in': f'{TEMP_FOLDER}/in',
		'data_folder_out': f'{TEMP_FOLDER}/out',
	},

	# Configuration du result backend
	'result_backend': CELERY_RESULT_BACKEND,
	'result_extended': True
})
workflow_processor = register_workflow_processor(app)


@signals.celeryd_init.connect
def setup_log_format(sender, conf, **kwargs):
    conf.worker_log_format = '[%(processName)s] %(message)s'
    # conf.worker_task_log_format = '[%(processName)s] [%(task_name)s(%(task_id)s)] %(message)s'


#--------------#
# Celery tasks #
#--------------#

def break_task(task_cls, task_opts, targets, results=[]):
	"""Break a task into multiple of the same type."""
	workflow = chain(
		forward_results.s(results),
		chord(
			(task_cls.s(input, **task_opts) for input in targets),
			forward_results.s()
		)
	)
	return workflow


@app.task(bind=True)
def run_command(self, results, name, target, opts={}):
	# console.print_item(json.dumps(results))

	# Flaten + dedupe results
	results = flatten(results)
	results = deduplicate(results, key='_uuid')

	# Get expanded targets
	_targets, opts = merge_extracted_values(results, opts)
	if not _targets:
		_targets = target

	# Get task
	task = [task for task in COMMANDS if task.__name__ == name]
	if not task:
		console.log(f'Task {name} not found. Aborting.', style='bold red')
		return
	task = task[0]

	# If task doesn't support multiple targets, split into multiple tasks
	if task.file_flag is None and isinstance(_targets, list):
		workflow = break_task(task, opts, _targets, results=results)
		sync = opts['sync']
		with allow_join_result():
			return workflow.apply().get() if sync else workflow().get()

	# Run task
	task_results = []
	count = 0
	self.update_state(
		state='PROGRESS',
		meta={'name': name, 'results': [], 'count': count}
	)
	for item in task(_targets, **opts):
		result_uuid = str(uuid.uuid4())
		item['_uuid'] = result_uuid
		task_results.append(item)
		results.append(item)
		count += 1
		self.update_state(
			state='PROGRESS',
			meta={'name': name, 'results': results, 'count': count}
		)
	return results


@app.task
def forward_results(*args, **kwargs):
	# Flatten + dedupe results
	results = flatten(args[0])
	results = deduplicate(results, key='_uuid')
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
				if item['_uuid'] not in seen:
					yield res.id, None, item
					seen.append(item['_uuid'])
			return

		# Get task partial results, remove duplicates
		results = res.info['results']
		name = res.info['name']
		for item in results:
			if item['_uuid'] not in seen:
				yield res.id, name, item
				seen.append(item['_uuid'])

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