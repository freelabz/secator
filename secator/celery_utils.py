import gc

from contextlib import nullcontext
from time import sleep

import kombu
import kombu.exceptions

from celery.result import AsyncResult, GroupResult
from celery.exceptions import TaskRevokedError
from greenlet import GreenletExit
from rich.panel import Panel
from rich.padding import Padding

from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
from secator.config import CONFIG
from secator.definitions import STATE_COLORS
from secator.output_types import Error, Info, Progress, State
from secator.rich import console
from secator.utils import debug, traceback_as_string


class CeleryData(object):
	"""Utility to simplify tracking a Celery task and all of its subtasks."""

	def iter_results(
		result,
		ids_map={},
		description=True,
		revoked=False,
		refresh_interval=CONFIG.runners.poll_frequency,
		print_remote_info=True,
		print_remote_title='Results',
	):
		"""Generator to get results from Celery task.

		Args:
			result (Union[AsyncResult, GroupResult]): Celery result.
			description (bool): Whether to show task description.
			revoked (bool): Whether the task was revoked.
			refresh_interval (int): Refresh interval.
			print_remote_info (bool): Whether to display live results.
			print_remote_title (str): Title for the progress panel.

		Yields:
			dict: Subtasks state and results.
		"""
		# Display live results if print_remote_info is set
		# Pre-compute main_result_id here (before inner loop shadows 'result').
		# exclude_main hides the workflow-level task from the panel when real subtasks are present.
		main_result_id = result.id
		exclude_main = any(tid != main_result_id for tid in ids_map)
		if print_remote_info:

			class PanelProgress(RichProgress):
				def get_renderables(self):
					yield Padding(
						Panel(
							self.make_tasks_table(self.tasks),
							title=print_remote_title,
							border_style='bold gold3',
							expand=False,
							highlight=True,
						),
						pad=(2, 0, 0, 0),
					)

			progress = PanelProgress(
				SpinnerColumn('dots'),
				TextColumn('{task.fields[descr]}  ') if description else '',
				TextColumn('[bold cyan]{task.fields[full_name]}[/]'),
				TextColumn('{task.fields[state]:<20}'),
				TimeElapsedColumn(),
				TextColumn('{task.fields[count]}'),
				TextColumn('{task.fields[progress]}%'),
				# TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),  # noqa: W605
				auto_refresh=False,
				transient=False,
				console=console,
				# redirect_stderr=True,
				# redirect_stdout=False,
			)
		else:
			progress = nullcontext()

		with progress:
			# Make initial progress
			if print_remote_info:
				progress_cache = CeleryData.init_progress(progress, ids_map, main_result_id if exclude_main else None)

			# Track yielded UUIDs to avoid re-yielding items on subsequent polls
			yielded_uuids = set()

			# Get live results and print progress
			for data in CeleryData.poll(result, ids_map, refresh_interval, revoked):
				for result in data['results']:
					# Skip already-yielded items (worker state accumulates all results each poll)
					if result._uuid and result._uuid in yielded_uuids:
						del result
						continue
					if result._uuid:
						yielded_uuids.add(result._uuid)
					# Add dynamic subtask to ids_map
					if isinstance(result, Info):
						message = result.message
						if message.startswith('Celery chunked task created'):
							task_id = message.split(' ')[-1]
							debug('chunked task recorded from remote info message', sub='celery.poll', id=task_id)
							ids_map[task_id] = {
								'id': task_id,
								'name': result._source,
								'full_name': result._source,
								'descr': '',
								'state': 'PENDING',
								'count': 0,
								'progress': 0,
							}
					yield result
					del result

				if print_remote_info:
					task_id = data['id']
					if exclude_main and task_id == main_result_id:
						continue
					is_chunk = ids_map.get(task_id, {}).get('chunk')
					if is_chunk:
						if exclude_main:
							continue  # hide chunk tasks in workflow panel
						# Show chunk tasks under main task for simple tasks
						if task_id not in progress_cache:
							progress_cache[task_id] = progress.add_task('', advance=0, **data)
						CeleryData.update_progress(progress, progress_cache[task_id], data)
						progress.refresh()
						continue
					if task_id not in progress_cache:
						if CONFIG.runners.show_subtasks:
							progress_cache[task_id] = progress.add_task('', advance=0, **data)
						else:
							continue
					CeleryData.update_progress(progress, progress_cache[task_id], data)
					progress.refresh()

				# Garbage collect between polls
				del data
				gc.collect()

			# Update all tasks to final state
			if print_remote_info:
				for task_id, progress_id in progress_cache.items():
					task_data = ids_map.get(task_id, {})
					task_state = task_data.get("state", "SUCCESS")
					if task_state not in STATE_COLORS:
						task_state = "SUCCESS"
					colored_state = f"[{STATE_COLORS[task_state]}]{task_state}[/]"
					progress.update(progress_id, state=colored_state, progress=100)
				progress.refresh()

	@staticmethod
	def init_progress(progress, ids_map, main_result_id=None):
		cache = {}
		for task_id, data in ids_map.items():
			if task_id == main_result_id:
				continue
			pdata = data.copy()
			state = data['state']
			pdata['state'] = f'[{STATE_COLORS[state]}]{state}[/]'
			if pdata.get('descr') and len(pdata['descr']) > 50:
				pdata['descr'] = pdata['descr'][:50] + '...'
			id = progress.add_task('', advance=0, **pdata)
			cache[task_id] = id
		return cache

	@staticmethod
	def update_progress(progress, progress_id, data):
		"""Update rich progress with fresh data."""
		pdata = data.copy()
		state = data['state']
		pdata['state'] = f'[{STATE_COLORS[state]}]{state}[/]'
		if pdata.get('descr') and len(pdata['descr']) > 50:
			pdata['descr'] = pdata['descr'][:50] + '...'
		pdata = {k: v for k, v in pdata.items() if v}
		progress.update(progress_id, **pdata)

	@staticmethod
	def poll(result, ids_map, refresh_interval, revoked=False):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Yields:
			dict: Subtasks state and results.
		"""
		exit_loop = False
		while not exit_loop:
			try:
				yield from CeleryData.get_all_data(result, ids_map, revoked=revoked)
				if result.ready() or revoked:
					debug('result is ready', sub='celery.poll', id=result.id)
					exit_loop = True
			except (KeyboardInterrupt, GreenletExit):
				debug('encounted KeyboardInterrupt or GreenletExit', sub='celery.poll')
				yield from CeleryData.get_all_data(result, ids_map, revoked=revoked)
				raise
			except Exception as e:
				error = Error.from_exception(e)
				debug(repr(error), sub='celery.poll')
				pass
			finally:
				sleep(refresh_interval)

	@staticmethod
	def get_all_data(result, ids_map, revoked=False):
		main_task = State(
			task_id=result.id,
			state='REVOKED' if revoked and result.state in ['PENDING', 'RUNNING'] else result.state,
			_source='celery',
		)
		debug(f'Main task state: {result.id} - {result.state}', sub='celery.poll', verbose=True)
		yield {'id': result.id, 'state': result.state, 'results': [main_task]}
		yield from CeleryData.get_tasks_data(ids_map, revoked=revoked)

	@staticmethod
	def get_tasks_data(ids_map, revoked=False):
		"""Get Celery results from main result object, AND all subtasks results.

		Yields:
			dict: Subtasks state and results.
		"""
		task_ids = list(ids_map.keys())
		for task_id in task_ids:
			data = CeleryData.get_task_data(task_id, ids_map)
			if not data:
				continue
			if revoked and data['state'] in ['PENDING', 'RUNNING']:
				data['state'] = 'REVOKED'
			debug(
				'POLL',
				sub='celery.poll',
				id=data['id'],
				obj={data['full_name']: data['state'], 'count': data['count']},
				verbose=True,
			)
			yield data

		# Compute chunk group completion from ids_map directly.
		# Completed chunk tasks are skipped by get_task_data (ready=True early return),
		# but their chunk/chunk_count/ready fields remain in ids_map from prior polls.
		chunk_groups = {}
		for tid, tdata in ids_map.items():
			chunk = tdata.get('chunk')
			chunk_count = tdata.get('chunk_count')
			debug('chunk scan', sub='celery.poll', id=tid, obj={'chunk': chunk, 'chunk_count': chunk_count, 'ready': tdata.get('ready'), 'name': tdata.get('name')})  # noqa: E501
			if chunk and chunk_count:
				name = tdata.get('name', '')
				if name not in chunk_groups:
					chunk_groups[name] = {'chunk_count': chunk_count, 'completed': 0}
				if tdata.get('ready', False):
					chunk_groups[name]['completed'] += 1
		debug('chunk_groups', sub='celery.poll', obj=chunk_groups)

		# Yield aggregate chunk progress for parent tasks
		for name, group in chunk_groups.items():
			total = group['chunk_count']
			completed = group['completed']
			percent = round(completed / total * 100, 1)
			parent_id = next(
				(tid for tid, tdata in ids_map.items() if tdata.get('name') == name and not tdata.get('chunk')),
				None,
			)
			debug('chunk progress', sub='celery.poll', obj={'name': name, 'percent': percent, 'parent_id': parent_id})
			if not parent_id:
				continue
			parent_data = ids_map[parent_id]
			if parent_data.get('state') in ['SUCCESS', 'FAILURE', 'REVOKED']:
				continue
			chunk_progress_states = parent_data.setdefault('_chunk_progress_states', set())
			state = (percent, completed, total)
			debug('chunk progress state', sub='celery.poll', obj={'state': state, 'already_seen': state in chunk_progress_states})  # noqa: E501
			if state in chunk_progress_states:
				continue
			chunk_progress_states.add(state)
			pg = Progress(percent=percent, extra_data={'completed': completed, 'total': total, 'force': True})
			pg._source = parent_data.get('full_name', name)
			yield {
				'id': parent_id,
				'name': name,
				'full_name': parent_data.get('full_name', name),
				'state': parent_data.get('state', 'RUNNING'),
				'count': parent_data.get('count', 0),
				'progress': percent,
				'descr': parent_data.get('descr', ''),
				'results': [pg],
			}

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
		data.update(
			{
				'state': res.state,
				'ready': False,
				'results': [],
			}
		)

		# Get remote task data
		info = res.info

		# Depending on the task state, info will be either an Exception (FAILURE), a list (SUCCESS), or a dict (RUNNING).
		# - If it's an Exception, it's a TaskRevokedError or an unhandled error.
		# - If it's a list, it's the task results.
		# - If it's a dict, it's the custom user metadata.

		if isinstance(info, Exception):
			if isinstance(info, TaskRevokedError):
				data['results'] = [Error(message='Task was revoked', _source=data['name'])]
				data['state'] = 'REVOKED'
				data['ready'] = True
			else:
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
