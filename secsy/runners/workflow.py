import uuid
from contextlib import nullcontext

from celery import chain, chord

from secsy.definitions import RECORD
from secsy.exporters import CsvExporter, JsonExporter, TableExporter
from secsy.output_types import Target
from secsy.rich import console
from secsy.runners._base import Runner
from secsy.runners.task import Task
from secsy.utils import merge_opts


class Workflow(Runner):

	DEFAULT_EXPORTERS = [
		TableExporter,
		JsonExporter,
		CsvExporter
	]

	DEFAULT_FORMAT_OPTIONS = {
		'print_timestamp': True,
		'print_cmd': True,
		'print_line': False,
		'print_item': False,
		'print_metric': True,
		'print_item_count': True,
		'raw_yield': False
	}

	def run(self, sync=True, results=[]):
		"""Run workflow.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		self.sync = sync

		# Overriding library defaults with CLI defaults
		fmt_opts = self.DEFAULT_FORMAT_OPTIONS.copy()
		fmt_opts['sync'] = sync

		# Check if we can add a console status
		print_line = self.run_opts.get('print_line', False)
		print_item = self.run_opts.get('print_item', False)
		print_metric = self.run_opts.get('print_metric', True)
		live_status = sync and not (print_line or print_item or print_metric)

		# In async mode, display results back in client-side
		if not sync:
			fmt_opts['print_cmd_prefix'] = True
			if not self.exporters:
				self.exporters = self.DEFAULT_EXPORTERS

		# Merge runtime options
		self.run_opts = merge_opts(self.run_opts, fmt_opts)

		# Log workflow start
		self.log_start()

		# Add target to results
		_uuid = str(uuid.uuid4())
		self.results = results + [
			Target(name=name, _source='workflow', _type='target', _uuid=_uuid)
			for name in self.targets
		]

		# Build Celery workflow
		workflow = self.build_celery_workflow(results=self.results)

		# Run Celery workflow and get results
		status = f'[bold yellow]Running workflow [bold magenta]{self.config.name} ...'
		with console.status(status) if not RECORD and live_status else nullcontext():
			if sync:
				result = workflow.apply()
			else:
				result = workflow()
				list(self.process_live_tasks(result))

		# Get workflow results
		results = result.get()
		self.results = results
		self.results = self.filter_results()
		self.done = True
		self.log_results()

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
				opts = merge_opts(workflow_opts, task_opts, run_opts)

				# Create task signature
				sig = task.s(targets, **opts)
			sigs.append(sig)
		return sigs
