from datetime import datetime
from time import sleep, time

import humanize
from celery.result import AsyncResult
from rich.progress import (Progress, SpinnerColumn, TextColumn,
						   TimeElapsedColumn)

from secsy.definitions import DEBUG
from secsy.output_types import OUTPUT_TYPES
from secsy.rich import console
from secsy.runners._helpers import (get_task_ids, get_task_info,
									process_extractor)
from secsy.utils import merge_opts
from secsy.report import Report


class Runner:
	"""Runner class.

	Args:
		config (secsy.config.ConfigLoader): Loaded config.
		targets (list): List of targets to run task on.
		results (list): List of existing results to re-use.
		workspace_name (str): Workspace name.
		expoters (list): List of exporter classes to use.
		run_opts (dict): Run options.

	Yields:
		dict: Result (when running in sync mode with `run`).

	Returns:
		list: List of results (when running in async mode with `run_async`).
	"""

	DEFAULT_EXPORTERS = []

	def __init__(self, config, targets, results=[], workspace_name=None, exporters=[], **run_opts):
		self.config = config
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.results = results
		self.workspace_name = workspace_name
		self.exporters = exporters or self.DEFAULT_EXPORTERS
		self.run_opts = run_opts
		self.done = False
		self.start_time = datetime.fromtimestamp(time())
		self.errors = []

	def log_start(self):
		"""Log runner start."""
		remote_str = 'starting' if self.sync else 'sent to [bold gold3]Celery[/] worker'
		runner_name = self.__class__.__name__
		console.print(
			f':tada: [bold green]{runner_name}[/] [bold magenta]{self.config.name}[/] [bold green]{remote_str}...[/]')
		self.log_header()

	def log_header(self):
		runner_name = self.__class__.__name__
		opts = merge_opts(self.run_opts, self.config.options)
		console.print()
		console.print(f'[bold gold3]{runner_name}:[/]    {self.config.name}')

		# Description
		description = self.config.description
		if description:
			console.print(f'[bold gold3]Description:[/] {description}')

		# Targets
		if self.targets:
			console.print('Targets: ', style='bold gold3')
			for target in self.targets:
				console.print(f' • {target}')

		# Options
		from secsy.decorators import DEFAULT_CLI_OPTIONS
		items = [
			f'[italic]{k}[/]: {v}'
			for k, v in opts.items()
			if not k.startswith('print_')
			and k not in DEFAULT_CLI_OPTIONS
			and v is not None
		]
		if items:
			console.print('Options:', style='bold gold3')
			for item in items:
				console.print(f' • {item}')

		console.print()

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

	@staticmethod
	def get_live_results(result):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Args:
			result (celery.result.AsyncResult): Result object.

		Yields:
			dict: Current task state and results.
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

	def process_live_tasks(self, result):
		tasks_progress = Progress(
			SpinnerColumn('dots'),
			TextColumn('[bold gold3]{task.fields[name]}[/]'),
			TextColumn('[dim gold3]{task.fields[chunk_info]}[/]'),
			TextColumn('{task.fields[state]:<20}'),
			TimeElapsedColumn(),
			TextColumn('{task.fields[count]}'),
			TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),  # noqa: W605
			refresh_per_second=1
		)
		state_colors = {
			'RUNNING': 'bold yellow',
			'SUCCESS': 'bold green',
			'FAILURE': 'bold red',
			'REVOKED': 'bold magenta'
		}
		with tasks_progress as progress:

			# Make progress tasks
			tasks_progress = {}

			# Get live results and print progress
			for info in Runner.get_live_results(result):

				# Re-yield so that we can consume it externally
				yield info

 				# Ignore partials in output unless DEBUG=1
				if info['chunk'] and not DEBUG:
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
		"""Filter results."""
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
