from celery.result import AsyncResult, GroupResult
from rich.panel import Panel
from rich.padding import Padding
from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
from contextlib import nullcontext
from secator.output_types import OutputType
from secator.utils import debug
from secator.rich import console
from secator.output_types import Progress
import kombu
import kombu.exceptions
from time import sleep


class CeleryData(object):
	"""Utility to simplify tracking a Celery task and all of it's subtasks."""

	# def __init__(self, result):
	# 	self._result = result
	# 	self.chunk_ids = []
	# 	self.errors = []
	# 	self.infos = []
	# 	self.progress = {}

	# def toDict(self):
	# 	return {
	# 		'id': self._result.id,
	# 		'chunk_ids': self.chunk_ids,
	# 		'task_ids': self.task_ids,
	# 		'progress': self.progress,
	# 	}

	@staticmethod
	def process_live_tasks(result, description=True, results_only=True, print_remote_status=True, print_remote_title='Results'):
		"""Rich progress indicator showing live tasks statuses.

		Args:
			result (AsyncResult | GroupResult): Celery result.
			results_only (bool): Yield only results, no task state.

		Yields:
			dict: Subtasks state and results.
		"""

		# Display live results if print_remote_status is set
		if print_remote_status:
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
			from secator.celery_utils import CeleryData
			for data in CeleryData.get_live_results(result):

				# If progress object, yield progress and ignore tracking
				if isinstance(data, OutputType) and data._type == 'progress':
					yield data
					continue

				# TODO: add error output type and yield errors in get_celery_results
				# if isinstance(data, OutputType) and data._type == 'error':
				# 	yield data
				# 	continue

				# Re-yield so that we can consume it externally
				if results_only:
					yield from data['results']
				else:
					yield data

				if not print_remote_status:
					continue

				# Handle messages if any
				state = data['state']
				error = data.get('error')
				info = data.get('info')
				full_name = data['name']
				chunk_info = data.get('chunk_info', '')
				# celery_chunk_ids = data.get('celery_chunk_ids', [])
				# celery_id = data['celery_id']
				# task_ids = [celery_id] + celery_chunk_ids
				# new_ids = [_ for _ in task_ids if _ not in self.celery_ids]
				# if new_ids:
					# debug(f'added new task ids {new_ids} to runner', sub='celery.state')
					# self.celery_ids.extend(new_ids)
				if chunk_info:
					full_name += f' {chunk_info}'
				if error:
					state = 'FAILURE'
					error = f'{full_name}: {error}'
					# if error not in self.errors:
						# self.errors.append(error)
				if info:
					info = f'{full_name}: {info}'
					# if info not in self.infos:
						# self.infos.append(info)

				task_id = data['id']
				state_str = f'[{state_colors[state]}]{state}[/]'
				data['state'] = state_str

				if task_id not in tasks_progress:
					id = progress.add_task('', **data)
					tasks_progress[task_id] = id
				else:
					progress_id = tasks_progress[task_id]
					if state in ['SUCCESS', 'FAILURE']:
						progress.update(progress_id, advance=100, **data)
					elif data['progress'] != 0:
						progress.update(progress_id, advance=data['progress'], **data)

			# Update all tasks to 100 %
			for progress_id in tasks_progress.values():
				progress.update(progress_id, advance=100)

	@staticmethod
	def get_live_results(result):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Args:
			result (celery.result.AsyncResult): Result object.

		Yields:
			dict: Subtasks state and results.
		"""
		res = AsyncResult(result.id)
		while True:
			# Yield results
			yield from CeleryData.get_celery_results(result)

			# Break out of while loop
			if res.ready():
				yield from CeleryData.get_celery_results(result)
				break

			# Sleep between updates
			sleep(1)

	@staticmethod
	def get_celery_results(result):
		"""Get Celery results from main result object, including any subtasks results.

		Args:
			result (celery.result.AsyncResult): Result object.

		Yields:
			dict: Subtasks state and results, Progress objects.
		"""
		task_ids = []
		CeleryData.get_task_ids(result, ids=task_ids)
		datas = []
		for task_id in task_ids:
			data = CeleryData.get_task_data(task_id)
			if not data:
				continue
			debug('', sub='celery.runner', id=data['id'], obj={data['full_name']: data['state']}, level=4)
			yield data
			datas.append(data)

		# Calculate and yield progress
		total = len(datas)
		count_finished = sum([i['ready'] for i in datas if i])
		percent = int(count_finished * 100 / total) if total > 0 else 0
		if percent > 0:
			yield Progress(duration='unknown', percent=percent)


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
			'celery_chunk_ids': [],
		}

		# Set ready flag
		if state in ['FAILURE', 'SUCCESS', 'REVOKED']:
			data['ready'] = True

		# Set task data
		if info and not isinstance(info, list):
			data.update(info)

		return data