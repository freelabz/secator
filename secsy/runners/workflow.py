from contextlib import nullcontext
from datetime import datetime
from time import time
import traceback

from celery import chain, chord

from secsy.rich import console
from secsy.runners._base import Runner
from secsy.runners.task import Task
from secsy.utils import merge_opts


class Workflow(Runner):
	"""Workflow runner.

	Args:
		config (secsy.config.ConfigLoader): Loaded config.
		targets (list): List of targets to run workflow on.
		run_opts (dict): Run options.

	Yields:
		dict: Result (when running in sync mode with `run`).

	Returns:
		list: List of results (when running in async mode with `run_async`).
	"""

	def run(self, sync=True, results=[], print_results=True):
		"""Run workflow.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery 
				worker in distributed mode.

		Returns:
			list: List of results.
		"""
		self._print_table = print_results
		self.sync = sync
		fmt_opts = {
			'print_timestamp': True,
			'print_cmd': True,
			'print_cmd_prefix': not sync,
			'print_item_count': True,
			'sync': sync,
		}
		self.run_opts = merge_opts(self.run_opts, fmt_opts)

		# Check if we can add a console status
		print_line = self.run_opts.get('print_line', False)
		print_item = self.run_opts.get('print_item', False)
		print_status = sync and not (print_line or print_item)

		# Log workflow start
		self.log_start()

		# Add target to results
		self.results = results + [
			{'name': name, '_source': 'workflow', '_type': 'target'}
			for name in self.targets
		]

		# Build Celery workflow
		workflow = self.build_celery_workflow(results=results)

		# Run Celery workflow and get results
		status = f'[bold yellow]Running workflow [bold magenta]{self.config.name} ...'
		with console.status(status) if print_status else nullcontext():
			if sync:
				result = workflow.apply()
			else:
				result = workflow()
				console.log(f'Celery workflow [bold magenta]{str(result)}[/] sent to broker.')
				self.process_live_tasks(result)

		# Get workflow results
		results = result.get()
		self.results = results
		self.results = self.filter_results()
		self.done = True
		self.log_workflow()
		
		return self.results

	def build_celery_workflow(self, results=[]):
		""""Build Celery workflow.

		Returns:
			celery.chain: Celery task chain.
		"""
		from secsy.celery import forward_results
		sigs = Workflow.get_tasks(
			self.config.tasks.toDict(),
			self.targets,
			self.config.options,
			self.run_opts)
		sigs = [forward_results.si(results)] + sigs + [forward_results.s()]
		workflow = chain(*sigs)
		return workflow

	@staticmethod
	def get_tasks(obj, targets, workflow_opts, run_opts):
		"""Get tasks recursively as Celery chains / chords.

		Args:
			obj (secsy.config.ConfigLoader): Config.
			targets (list): List of targets.
			workflow_opts (dict): Workflow options.
			run_opts (dict): Run options.
			sync (bool): Synchronous mode (chain of tasks, no chords).

		Returns:
			list: List of signatures.
		"""
		from secsy.celery import forward_results
		sigs = []
		for task_name, task_opts in obj.items():
			# Task opts can be None
			task_opts = task_opts or {}

			# If it's a group, process the sublevel tasks as a Celery chord.
			if task_name == '_group':
				tasks = Workflow.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts)
				sig = chord((tasks), forward_results.s())
			elif task_name == '_chain':
				tasks = Workflow.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts
				)
				sig = chain(*tasks)
			else:
				# Get task class
				task = Task.get_task_class(task_name)

				# Merge task options (order of priority with overrides)
				opts = merge_opts(run_opts, workflow_opts, task_opts)

				# Create task signature
				sig = task.s(targets, **opts)
			sigs.append(sig)
		return sigs

	def log_start(self):
		"""Log workflow start."""
		self.start_time = datetime.fromtimestamp(time())
		remote_str = 'starting' if self.sync else 'sent to [bold gold3]Celery[/] worker'
		console.print(f':tada: [bold green]Workflow[/] [bold magenta]{self.config.name}[/] [bold green]{remote_str}...[/]')
		self.log_workflow()

	def log_workflow(self):
		"""Log workflow."""
		# Print workflow options
		if not self.done:
			opts = merge_opts(self.run_opts, self.config.options)
			console.print()
			console.print(f'[bold gold3]Workflow:[/]    {self.config.name}')

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
				if not k.startswith('print_') \
					and k not in DEFAULT_CLI_OPTIONS \
					and v is not None
			]
			if items:
				console.print('Options:', style='bold gold3')
				for item in items:
					console.print(f' • {item}')
			
			console.print()

		# Print workflow results
		self.log_results()