from contextlib import nullcontext
from datetime import datetime
from time import sleep, time

import humanize
from celery.result import AsyncResult
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (Progress, SpinnerColumn, TextColumn,
						   TimeElapsedColumn)

from secsy.definitions import DEBUG
from secsy.output_types import OUTPUT_TYPES
from secsy.report import Report
from secsy.rich import console
from secsy.runners._helpers import (get_task_ids, get_task_info,
									process_extractor)
from secsy.utils import import_dynamic, merge_opts


class Runner:
	"""Runner class.

	Args:
		config (secsy.config.ConfigLoader): Loaded config.
		targets (list): List of targets to run task on.
		results (list): List of existing results to re-use.
		workspace_name (str): Workspace name.
		run_opts (dict): Run options.

	Yields:
		dict: Result (when running in sync mode with `run`).

	Returns:
		list: List of results (when running in async mode with `run_async`).
	"""

	DEFAULT_EXPORTERS = []

	def __init__(self, config, targets, results=[], workspace_name=None, run_opts={}, hooks={}, context={}):
		self.config = config
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.results = results
		self.workspace_name = workspace_name
		self.run_opts = run_opts
		self.sync = run_opts.get('sync', True)
		self.exporters = self.resolve_exporters()
		self.done = False
		self.start_time = datetime.fromtimestamp(time())
		self.errors = []
		self.context = context
		self.hooks = hooks
		self.delay = run_opts.get('delay', False)
		self.run_hooks('on_init')

	def toDict(self):
		return {
			'config': self.config.toDict(),
			'targets': self.targets,
			'workspace_name': self.workspace_name,
			'run_opts': self.run_opts,
			'sync': self.sync,
			'done': self.done,
			'start_time': self.start_time,
			'errors': self.errors,
			'context': self.context,
		}

	def run_hooks(self, hook_type, *args):
		# logger.debug(f'Running hooks of type {hook_type}')
		result = args[0] if len(args) > 0 else None
		for hook in self.hooks.get(self.__class__, {}).get(hook_type, []):
			# logger.debug(hook)
			result = hook(self, *args)
		return result

	def resolve_exporters(self):
		"""Resolve exporters from output options."""
		output = self.run_opts.get('output', None)
		if output is None:
			return self.DEFAULT_EXPORTERS
		elif output is False:
			return []
		exporters = [
			import_dynamic(f'secsy.exporters.{o.capitalize()}Exporter', 'Exporter')
			for o in output.split(',')
			if o
		]
		return [e for e in exporters if e]

	def log_start(self):
		"""Log runner start."""
		remote_str = 'starting' if self.sync else 'sent to Celery worker'
		runner_name = self.__class__.__name__
		self.log_header()
		console.print(
			f':tada: {runner_name} [bold magenta]{self.config.name}[/] {remote_str}...')

	def log_header(self):
		"""Log runner header."""
		runner_name = self.__class__.__name__
		opts = merge_opts(self.config.options, self.run_opts)
		console.print()

		# Description
		panel_str = f':scroll: [bold gold3]Description:[/] {self.config.description}'

		# Workspace
		if self.workspace_name:
			panel_str += f'\n:construction_worker: [bold gold3]Workspace:[/] {self.workspace_name}'

		# Targets
		if self.targets:
			panel_str += '\n:pear: [bold gold3]Targets:[/]'
			for target in self.targets:
				panel_str += f'\n   • {target}'

		# Options
		DISPLAY_OPTS_EXCLUDE = [
			'sync', 'worker', 'debug', 'output', 'json', 'orig', 'raw', 'format', 'color', 'table', 'quiet', 'raw_yield'
		]
		items = [
			f'[italic]{k}[/]: {v}'
			for k, v in opts.items()
			if not k.startswith('print_') and k not in DISPLAY_OPTS_EXCLUDE
			and v is not None
		]
		if items:
			panel_str += '\n:pushpin: [bold gold3]Options:[/]'
			for item in items:
				panel_str += f'\n   • {item}'

		if self.exporters:
			panel_str += '\n:email:  [bold gold3]Exporters:[/]'
			for exporter in self.exporters:
				exporter_name = exporter.__name__.replace('Exporter', '').lower()
				panel_str += f'\n   • {exporter_name}'

		panel = Panel(
			panel_str,
			title=f'[bold gold3]{runner_name}[/] [bold magenta]{self.config.name}[/]',
			border_style='bold gold3',
			expand=False,
			highlight=True
		)
		console.print(panel)

	def log_results(self):
		"""Log results.

		Args:
			results (list): List of results.
			output_types (list): List of result types to add to report.
		"""
		for error in self.errors:
			console.log(error, style='bold red')

		if not self.done:
			return

		if not self.results:
			console.log('No results found.', style='bold red')
			return

		self.end_time = datetime.fromtimestamp(time())
		self.elapsed = self.end_time - self.start_time
		self.elapsed_human = humanize.naturaldelta(self.elapsed)
		console.print()

		# Build and send report
		report = Report(self, exporters=self.exporters)
		report.build()
		report.send()
		self.report = report

		# Log execution results
		console.print(
			f':tada: [bold green]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.config.name}[/] '
			f'[bold green]finished successfully in[/] [bold gold3]{self.elapsed_human}[/].')
		console.print()
		self.run_hooks('on_end')

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
			task_ids = []
			get_task_ids(result, ids=task_ids)
			for task_id in task_ids:
				info = get_task_info(task_id)
				if not info:
					continue
				yield info

			# Break out of while loop
			if res.ready():
				break

			# Sleep between updates
			sleep(1)

	def process_live_tasks(self, result, description=True, results_only=True, print_live_status=True):
		"""Rich progress indicator showing live tasks statuses.

		Args:
			result (AsyncResult | GroupResult): Celery result.
			results_only (bool): Yield only results, no task state.

		Yields:
			dict: Subtasks state and results.
		"""
		config_name = self.config.name
		runner_name = self.__class__.__name__.capitalize()

		# Display live results if print_live_status is set
		if print_live_status:
			class PanelProgress(Progress):
				def get_renderables(self):
					yield Padding(Panel(
						self.make_tasks_table(self.tasks),
						title=f'[bold gold3]{runner_name}[/] [bold magenta]{config_name}[/] tasks',
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
				# TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),  # noqa: W605
				refresh_per_second=1
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
			for info in Runner.get_live_results(result):

				# Re-yield so that we can consume it externally
				if results_only:
					yield from info['results']
				else:
					yield info

				if not print_live_status:
					continue

 				# Ignore partials in output unless DEBUG > 1
				# TODO: weird to change behavior based on debug flag, could cause issues
				if info['chunk'] and not DEBUG > 1:
					continue

				# Handle error if any
				# TODO: error handling should be moved to process_live_tasks
				state = info['state']
				if info['error']:
					state = 'FAILURE'
					error = 'Error in task {name} {chunk_info}:\n{error}'.format(**info)
					if error not in self.errors:
						self.errors.append(error)

				task_id = info['id']
				state_str = f'[{state_colors[state]}]{state}[/]'
				info['state'] = state_str

				if task_id not in tasks_progress:
					id = progress.add_task('', **info)
					tasks_progress[task_id] = id
				else:
					progress_id = tasks_progress[task_id]
					if state in ['SUCCESS', 'FAILURE']:
						progress.update(progress_id, advance=100, **info)

			# Update all tasks to 100 %
			for progress_id in tasks_progress.values():
				progress.update(progress_id, advance=100)

	def filter_results(self):
		"""Filter runner results using extractors defined in config."""
		extractors = self.config.results
		results = []
		if extractors:
			# Keep results based on extractors
			opts = merge_opts(self.config.options, self.run_opts)
			for extractor in extractors:
				tmp = process_extractor(self.results, extractor, ctx=opts)
				results.extend(tmp)

			# Keep the field types in results not specified in the extractors.
			extract_fields = [e['type'] for e in extractors]
			keep_fields = [
				_type for _type in OUTPUT_TYPES
				if _type not in extract_fields
			]
			results.extend([
				item for item in self.results
				if item._type in keep_fields
			])
		else:
			results = self.results
		return results
