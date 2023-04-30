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
	DEFAULT_LIVE_DISPLAY_TYPES = ['vulnerability', 'tag']

	@classmethod
	def delay(cls, *args, **kwargs):
		from secsy.celery import run_workflow
		return run_workflow.delay(args=args, kwargs=kwargs)

	def yielder(self):
		"""Run workflow.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Add target to results and yield previous results
		self.results = self.results + [
			Target(name=name, _source='workflow', _type='target', _uuid=str(uuid.uuid4()), _context=self.context)
			for name in self.targets
		]
		yield from self.results
		self.results_count = len(self.results)

		# Build Celery workflow
		workflow = self.build_celery_workflow(results=self.results)

		# Run Celery workflow and get results
		status = f'[bold yellow]Running workflow [bold magenta]{self.config.name} ...'
		with console.status(status) if not RECORD and self.print_live_status else nullcontext():
			if self.sync:
				results = workflow.apply().get()
			else:
				result = workflow()
				self.print_live_status = True
				results = self.process_live_tasks(result, results_only=True, print_live_status=self.print_live_status)

		# Get workflow results
		yield from results

	def build_celery_workflow(self, results=[]):
		""""Build Celery workflow.

		Returns:
			celery.chain: Celery task chain.
		"""
		from secsy.celery import forward_results
		sigs = self.get_tasks(
			self.config.tasks.toDict(),
			self.targets,
			self.config.options,
			self.run_opts,
			self.hooks,
			self.context)
		sigs = [forward_results.si(results)] + sigs + [forward_results.s()]
		workflow = chain(*sigs)
		return workflow

	def get_tasks(self, obj, targets, workflow_opts, run_opts, hooks={}, context={}):
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
				tasks = self.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts,
					hooks,
					context
				)
				sig = chord((tasks), forward_results.s())
			elif task_name == '_chain':
				tasks = self.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts,
					hooks,
					context
				)
				sig = chain(*tasks)
			else:
				# Get task class
				task = Task.get_task_class(task_name)

				# Merge task options (order of priority with overrides)
				opts = merge_opts(workflow_opts, task_opts, run_opts)

				# Add task context and hooks to options
				opts['context'] = context
				opts['hooks'] = hooks.get(Task, {})

				# Create task signature
				sig = task.s(targets, **opts)
				self.output_types.extend(task.output_types)
			sigs.append(sig)
		return sigs
