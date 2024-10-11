from celery.result import AsyncResult, GroupResult
from rich.panel import Panel
from rich.padding import Padding
from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
from contextlib import nullcontext
from secator.output_types import Progress
from secator.utils import debug
from secator.rich import console
import kombu
import kombu.exceptions
from time import sleep


class CeleryData(object):
	"""Utility to simplify tracking a Celery task and all of its subtasks."""

	def iter_results(
			result,
			description=True,
			results_only=True,
			refresh_interval=1,
			print_remote_info=True,
			print_remote_title='Results'
		):
		"""Generator to get results from Celery task.

		Args:
			description (bool): Whether to show task description.
			results_only (bool): Yield only results, no task state.
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

			tasks_progress = PanelProgress(
				SpinnerColumn('dots'),
				TextColumn('{task.fields[descr]}  ') if description else '',
				TextColumn('[bold cyan]{task.fields[name]}[/]'),
				TextColumn('[dim gold3]{task.fields[chunk_info]}[/]'),
				TextColumn('{task.fields[state]:<20}'),
				TimeElapsedColumn(),
				TextColumn('{task.fields[count]}'),
				# TextColumn('{task.fields[progress]}%'),
				# TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),  # noqa: W605
				refresh_per_second=1,
				transient=False,
				# console=console,
				# redirect_stderr=True,
				# redirect_stdout=False
			)
			state_colors = {
				'RUNNING': 'bold yellow',
				'SUCCESS': 'bold green',
				'FAILURE': 'bold red',
				'REVOKED': 'bold magenta'
			}
		else:
			tasks_progress = nullcontext()

		with tasks_progress as progress:
			# Make progress tasks
			tasks_progress = {}

			# Get live results and print progress
			for data in CeleryData.poll(result, refresh_interval=refresh_interval):
				# Re-yield so that we can consume it externally
				if results_only:
					yield from data['results']
				else:
					yield data

				if not print_remote_info:
					continue

				# Handle messages if any
				state = data['state']
				task_id = data['id']
				progress_obj = data.get('progress', None)
				progress_data = data.copy()
				progress_data['state'] = f'[{state_colors[state]}]{state}[/]'

				if task_id not in tasks_progress:
					id = progress.add_task('', **progress_data)
					tasks_progress[task_id] = id
				else:
					progress_id = tasks_progress[task_id]
					if state in ['SUCCESS', 'FAILURE']:
						progress.update(progress_id, advance=100, **progress_data)
					elif progress_obj:
						progress.update(progress_id, advance=progress_obj.percent, **progress_data)

			# Update all tasks to 100 %
			for progress_id in tasks_progress.values():
				progress.update(progress_id, advance=100)

	@staticmethod
	def poll(result, refresh_interval=1):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Yields:
			dict: Subtasks state and results.
		"""
		while True:
			yield from CeleryData.get_all_data(result)
			if result.ready():
				debug('RESULT READY', sub='celery.runner', id=result.id)
				yield from CeleryData.get_all_data(result)
				break
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
				obj={data['full_name']: data['state'], 'results_count': data['count']},
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
		data['progress'] = Progress(duration='unknown', percent=percent)
		data['results'] = []
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
			return
		try:
			args = res.args
			info = res.info
			state = res.state
		except kombu.exceptions.DecodeError as e:
			console.print(f'[bold red]{str(e)}. Aborting get_task_data.[/]')
			return
		if not (args and len(args) > 1):
			return
		task_name = args[1]
		data = {
			'id': task_id,
			'name': task_name,
			'full_name': task_name,
			'state': state,
			'chunk_info': '',
			'count': 0,
			'error': None,
			'ready': False,
			'descr': '',
			'progress': 0,
			'results': [],
			'celery_id': '',
		}

		# Set ready flag
		if state in ['FAILURE', 'SUCCESS', 'REVOKED']:
			data['ready'] = True

		# Set task data
		if info and isinstance(info, dict):
			data.update(info)

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

			if hasattr(result, 'children') and result.children:
				for child in result.children:
					CeleryData.get_task_ids(child, ids=ids)

			# Browse parent
			if hasattr(result, 'parent') and result.parent:
				CeleryData.get_task_ids(result.parent, ids=ids)
		except kombu.exceptions.DecodeError as e:
			console.print(f'[bold red]{str(e)}. Aborting get_task_ids.[/]')
			return
