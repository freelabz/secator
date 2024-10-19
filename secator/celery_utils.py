from celery.result import AsyncResult, GroupResult
from rich.panel import Panel
from rich.padding import Padding
from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
from contextlib import nullcontext
from secator.definitions import STATE_COLORS
from secator.utils import debug, traceback_as_string
from secator.rich import console
from secator.config import CONFIG
import kombu
import kombu.exceptions
from time import sleep


class CeleryData(object):
	"""Utility to simplify tracking a Celery task and all of its subtasks."""

	def iter_results(
			result,
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
			from rich.console import Console
			console = Console()
			tasks_progress = PanelProgress(
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
			tasks_progress = nullcontext()

		with tasks_progress as progress:
			# Make progress tasks
			tasks_progress = {}

			# Get live results and print progress
			for data in CeleryData.poll(result, refresh_interval):
				yield from data['results']

				if not print_remote_info:
					continue

				# Handle messages if any
				task_id = data['id']
				progress_int = data.get('progress', None)
				progress_data = data.copy()

				# Set state progress data
				state = data['state']
				if state in STATE_COLORS:
					progress_data['state'] = f'[{STATE_COLORS[state]}]{state}[/]'
				else:
					progress_data['state'] = state

				if task_id not in tasks_progress:
					id = progress.add_task('', advance=0, **progress_data)
					tasks_progress[task_id] = id
				else:
					progress_id = tasks_progress[task_id]
					progress.update(progress_id, **progress_data)
					if progress_int:
						progress.update(progress_id, advance=progress_int)

			# Update all tasks to 100 %
			for progress_id in tasks_progress.values():
				progress.update(progress_id, advance=100)

	@staticmethod
	def poll(result, refresh_interval):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Yields:
			dict: Subtasks state and results.
		"""
		while True:
			try:
				yield from CeleryData.get_all_data(result)
				if result.ready():
					debug('RESULT READY', sub='celery.runner', id=result.id)
					yield from CeleryData.get_all_data(result)
					break
			except kombu.exceptions.DecodeError:
				debug('kombu decode error', sub='celerydebug', id=result.id)
				pass
			finally:
				sleep(refresh_interval)

	@staticmethod
	def get_all_data(result):
		"""Get Celery results from main result object, AND all subtasks results.

		Yields:
			dict: Subtasks state and results.
		"""
		task_ids = []
		CeleryData.get_task_ids(result, ids=task_ids)
		datas = []
		for task_id in task_ids:
			data = CeleryData.get_task_data(task_id)
			if not data:
				continue
			debug(
				'POLL',
				sub='celery.runner',
				id=data['id'],
				obj={data['full_name']: data['state'], 'count': data['count']},
				level=4
			)
			yield data
			datas.append(data)

		# Calculate and yield progress
		if not datas:
			return
		total = len(datas)
		count_finished = sum([i['ready'] for i in datas if i])
		percent = int(count_finished * 100 / total) if total > 0 else 0
		data = datas[-1]
		data['progress'] = percent
		yield data

	@staticmethod
	def get_task_data(task_id):
		"""Get task info.

		Args:
			task_id (str): Celery task id.

		Returns:
			dict: Task info (id, name, state, results, chunk_info, count, error, ready).
		"""
		res = AsyncResult(task_id)
		if not res:
			debug('empty response', sub='celerydebug', id=task_id)
			return

		# Get task data
		args = res.args
		info = res.info
		state = res.state

		# Task data not ready yet
		if not info:
			debug('empty data', sub='celerydebug', id=task_id)
			return

		# Set up task data
		data = {
			'id': task_id,
			'state': state,
			'name': '',
			'full_name': '',
			'count': 0,
			'ready': False,
			'descr': '',
			'progress': None,
			'results': [],
		}

		# Depending on the task state, info will be either an Exception (FAILURE), a list (SUCCESS), or a dict (RUNNING).
		# - If it's an Exception, it's an unhandled error.
		# - If it's a list, it's the task results.
		# - If it's a dict, it's the custom user metadata.

		if isinstance(info, Exception):
			debug('unhandled exception', obj={'msg': str(info), 'tb': traceback_as_string(info)}, sub='celerydebug', id=task_id)
			data['state'] = state
			raise info

		elif isinstance(info, list):
			data['results'] = info
			errors = [e for e in info if e._type == 'error']
			data['count'] = len(info)
			data['state'] = 'FAILURE' if errors else 'SUCCESS'
			if not args or len(args) < 2:
				debug('got results but args is undefined', obj={'args': args}, sub='celerydebug', id=task_id)
				return
			data['name'] = args[1]
			data['full_name'] = args[1]

		elif isinstance(info, dict):
			data.update(info)

		# Set ready flag and progress
		data['ready'] = data['state'] in ['FAILURE', 'SUCCESS', 'REVOKED']
		if data['ready']:
			data['progress'] = 100
		elif data['results']:
			progresses = [e for e in data['results'] if e._type == 'progress' and e._source == data['name']]
			if progresses:
				data['progress'] = progresses[-1].percent

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

		except kombu.exceptions.DecodeError as e:
			console.print(f'[bold red]{str(e)}. Aborting get_task_ids.[/]')
			return
