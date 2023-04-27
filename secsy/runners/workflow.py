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

	def run(self):
		return list(self.__iter__())

	def __iter__(self):
		"""Run workflow.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Overriding library defaults with CLI defaults
		fmt_opts = self.DEFAULT_FORMAT_OPTIONS.copy()
		fmt_opts['sync'] = self.sync

		# Check if we can add a console status
		print_line = self.run_opts.get('print_line', False)
		print_item = self.run_opts.get('print_item', False)
		print_metric = self.run_opts.get('print_metric', True)
		print_live_status = self.run_opts.get('print_live_status', True) or (self.sync and not (print_line or print_item or print_metric))

		# In async mode, display results back in client-side
		if not self.sync:
			fmt_opts['print_cmd_prefix'] = True
			if not self.exporters:
				self.exporters = self.DEFAULT_EXPORTERS

		# Merge runtime options
		self.run_opts = merge_opts(self.run_opts, fmt_opts)

		# Log workflow start
		self.log_start()

		# Add target to results and yield previous results
		_uuid = str(uuid.uuid4())
		self.results = self.results + [
			Target(name=name, _source='workflow', _type='target', _uuid=_uuid, _context=self.context)
			for name in self.targets
		]
		uuids = [i._uuid for i in self.results]
		yield from self.results

		# Build Celery workflow
		workflow = self.build_celery_workflow(results=self.results)

		# Run Celery workflow and get results
		status = f'[bold yellow]Running workflow [bold magenta]{self.config.name} ...'
		with console.status(status) if not RECORD and print_live_status else nullcontext():
			if self.sync:
				# TODO: yield live results here: doesn't work with apply, we will need to run something like:
				#  results = []
				#  for task in self.get_tasks():
				#	yield from Task(task, results=results)
				#	for item in Task(task, results=results):
				#		yield item
				#		results.append(item)
				results = workflow.apply().get()
			else:
				result = workflow()
				results = self.process_live_tasks(result, results_only=True, print_live_status=print_live_status)

		# Get workflow results
		display_types = self.DEFAULT_LIVE_DISPLAY_TYPES
		display_types_str = ', '.join(f'[bold yellow]{t}[/]' for t in display_types)
		console.print()
		if print_live_status:
			console.print(f':tv: Monitoring {display_types_str}:')
		for result in results:
			if result._uuid in uuids:
				continue
			if print_live_status and result._type in display_types:
				print(str(result))
			uuids.append(result._uuid)
			self.results.append(result)
			yield result

		# Filter workflow results
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
			self.run_opts,
			self.hooks,
			self.context)
		sigs = [forward_results.si(results)] + sigs + [forward_results.s()]
		workflow = chain(*sigs)
		return workflow

	@staticmethod
	def get_tasks(obj, targets, workflow_opts, run_opts, hooks={}, context={}):
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
					run_opts,
					hooks,
					context
				)
				sig = chord((tasks), forward_results.s())
			elif task_name == '_chain':
				tasks = Workflow.get_tasks(
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
			sigs.append(sig)
		return sigs
