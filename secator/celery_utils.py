from contextlib import nullcontext
from time import sleep

import kombu
import kombu.exceptions

from celery.result import AsyncResult, GroupResult
from greenlet import GreenletExit
from rich.panel import Panel
from rich.padding import Padding

from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
from secator.config import CONFIG
from secator.definitions import STATE_COLORS
from secator.output_types import Error, Info, State
from secator.rich import console
from secator.utils import debug, traceback_as_string


class CeleryData(object):
	"""Utility to simplify tracking a Celery task and all of its subtasks."""

	def iter_results(
			result,
			ids_map={},
			description=True,
			refresh_interval=CONFIG.runners.poll_frequency,
			print_remote_info=True,
			print_remote_title='Results'
		):
		"""Generator to get results from Celery task.

		Args:
			result (Union[AsyncResult, GroupResult]): Celery result.
			description (bool): Whether to show task description.
			refresh_interval (int): Refresh interval.
			print_remote_info (bool): Whether to display live results.
			print_remote_title (str): Title for the progress panel.

		Yields:
			dict: Subtasks state and results.
		"""
		# Display live results if print_remote_info is set
		if print_remote_info:
			class PanelProgress(RichProgress):
				def get_renderables(self):
					yield Padding(Panel(
						self.make_tasks_table(self.tasks),
						title=print_remote_title,
						border_style='bold gold3',
						expand=False,
						highlight=True), pad=(2, 0, 0, 0))
			progress = PanelProgress(
				SpinnerColumn('dots'),
				TextColumn('{task.fields[descr]}  ') if description else '',
				TextColumn('[bold cyan]{task.fields[full_name]}[/]'),
				TextColumn('{task.fields[state]:<20}'),
				TimeElapsedColumn(),
				TextColumn('{task.fields[count]}'),
				TextColumn('{task.fields[progress]}%'),
				# TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),  # noqa: W605
				refresh_per_second=1,
				transient=False,
				console=console,
				# redirect_stderr=True,
				# redirect_stdout=False
			)
		else:
			progress = nullcontext()

		with progress:

			# Make initial progress
			if print_remote_info:
				progress_cache = CeleryData.init_progress(progress, ids_map)

			# Get live results and print progress
			for data in CeleryData.poll(result, ids_map, refresh_interval):
				for result in data['results']:

					# Add dynamic subtask to ids_map
					if isinstance(result, Info):
						message = result.message
						if message.startswith('Celery chunked task created: '):
							task_id = message.split(' ')[-1]
							ids_map[task_id] = {
								'id': task_id,
								'name': result._source,
								'full_name': result._source,
								'descr': '',
								'state': 'PENDING',
								'count': 0,
								'progress': 0
							}
					yield result

				if print_remote_info:
					task_id = data['id']
					if task_id not in progress_cache:
						if CONFIG.runners.show_subtasks:
							progress_cache[task_id] = progress.add_task('', advance=0, **data)
						else:
							continue
					progress_id = progress_cache[task_id]
					CeleryData.update_progress(progress, progress_id, data)

			# Update all tasks to 100 %
			if print_remote_info:
				for progress_id in progress_cache.values():
					progress.update(progress_id, advance=100)

	@staticmethod
	def init_progress(progress, ids_map):
		cache = {}
		for task_id, data in ids_map.items():
			pdata = data.copy()
			state = data['state']
			pdata['state'] = f'[{STATE_COLORS[state]}]{state}[/]'
			id = progress.add_task('', advance=0, **pdata)
			cache[task_id] = id
		return cache

	@staticmethod
	def update_progress(progress, progress_id, data):
		"""Update rich progress with fresh data."""
		pdata = data.copy()
		state = data['state']
		pdata['state'] = f'[{STATE_COLORS[state]}]{state}[/]'
		pdata = {k: v for k, v in pdata.items() if v}
		progress.update(progress_id, **pdata)

	@staticmethod
	def poll(result, ids_map, refresh_interval):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Yields:
			dict: Subtasks state and results.
		"""
		while True:
			try:
				main_task = State(
					task_id=result.id,
					state=result.state,
					_source='celery'
				)
				debug(f"Main task state: {result.id} - {result.state}", sub='celery.poll', verbose=True)
				yield {'id': result.id, 'results': [main_task]}
				yield from CeleryData.get_all_data(result, ids_map)

				if result.ready():
					debug('result is ready', sub='celery.poll', id=result.id)
					main_task = State(
						task_id=result.id,
						state=result.state,
						_source='celery'
					)
					debug(f"Final main task state: {result.id} - {result.state}", sub='celery.poll', verbose=True)
					yield {'id': result.id, 'results': [main_task]}
					yield from CeleryData.get_all_data(result, ids_map)
					break
			except (KeyboardInterrupt, GreenletExit):
				debug('encounted KeyboardInterrupt or GreenletExit', sub='celery.poll')
				raise
			except Exception as e:
				error = Error.from_exception(e)
				debug(repr(error), sub='celery.poll')
				pass
			finally:
				sleep(refresh_interval)

	@staticmethod
	def get_all_data(result, ids_map):
		"""Get Celery results from main result object, AND all subtasks results.

		Yields:
			dict: Subtasks state and results.
		"""
		task_ids = list(ids_map.keys())
		for task_id in task_ids:
			data = CeleryData.get_task_data(task_id, ids_map)
			if not data:
				continue
			debug(
				'POLL',
				sub='celery.poll',
				id=data['id'],
				obj={data['full_name']: data['state'], 'count': data['count']},
				verbose=True
			)
			yield data

		# Calculate and yield parent task progress
		# if not datas:
		# 	return
		# total = len(datas)
		# count_finished = sum([i['ready'] for i in datas if i])
		# percent = int(count_finished * 100 / total) if total > 0 else 0
		# parent_id = [c for c in ids_map.values() if c['full_name'] == datas[-1]]
		# data['progress'] = percent
		# yield data

	@staticmethod
	def get_task_data(task_id, ids_map):
		"""Get task info.

		Args:
			task_id (str): Celery task id.

		Returns:
			dict: Task info (id, name, state, results, chunk_info, count, error, ready).
		"""

		# Get task data
		data = ids_map.get(task_id, {})
		if not data:
			ids_map[task_id] = {}
		elif data.get('ready', False):
			return

		# if not data:
		# 	debug('task not in ids_map', sub='debug.celery', id=task_id)
		# 	return

		# Get remote result
		res = AsyncResult(task_id)
		if not res:
			debug('empty response', sub='celery.data', id=task_id)
			return

		# Set up task state
		data.update({
			'state': res.state,
			'ready': False,
			'results': []
		})

		# Get remote task data
		info = res.info

		# Depending on the task state, info will be either an Exception (FAILURE), a list (SUCCESS), or a dict (RUNNING).
		# - If it's an Exception, it's an unhandled error.
		# - If it's a list, it's the task results.
		# - If it's a dict, it's the custom user metadata.

		if isinstance(info, Exception):
			debug('unhandled exception', obj={'msg': str(info), 'tb': traceback_as_string(info)}, sub='celery.data', id=task_id)
			raise info

		elif isinstance(info, list):
			data['results'] = info
			errors = [e for e in info if e._type == 'error']
			status = 'FAILURE' if errors else 'SUCCESS'
			data['count'] = len([c for c in info if c._source.startswith(data['name'])])
			data['state'] = status

		elif isinstance(info, dict):
			data.update(info)

		# Set ready flag and progress
		ready = data['state'] in ['FAILURE', 'SUCCESS', 'REVOKED']
		data['ready'] = ready
		ids_map[task_id]['ready'] = data['ready']
		if data['ready']:
			data['progress'] = 100
		elif data['results']:
			progresses = [e for e in data['results'] if e._type == 'progress' and e._source == data['full_name']]
			if progresses:
				data['progress'] = progresses[-1].percent

		debug('data', obj=data, sub='celery.data', id=task_id, verbose=True)
		return data

	@staticmethod
	def get_task_ids(result, ids=[]):
		"""Get all Celery task ids recursively.

		Args:
			result (Union[AsyncResult, GroupResult]): Celery result object.
			ids (list): List of ids.
		"""
		if result is None:
			return

		try:
			if isinstance(result, GroupResult):
				CeleryData.get_task_ids(result.parent, ids=ids)

			elif isinstance(result, AsyncResult):
				if result.id not in ids:
					ids.append(result.id)

			if hasattr(result, 'children'):
				children = result.children
				if isinstance(children, list):
					for child in children:
						CeleryData.get_task_ids(child, ids=ids)

			# Browse parent
			if hasattr(result, 'parent') and result.parent:
				CeleryData.get_task_ids(result.parent, ids=ids)

		except kombu.exceptions.DecodeError:
			debug('kombu decode error', sub='celery.data')
			return
