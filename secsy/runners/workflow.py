from celery import chain, chord

from secsy.exporters import CsvExporter, JsonExporter, TableExporter
from secsy.runners._base import Runner
from secsy.runners.task import Task
from secsy.utils import merge_opts
from secsy.output_types import Target


class Workflow(Runner):

	default_exporters = [
		TableExporter,
		JsonExporter,
		CsvExporter
	]

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
		# Yield targets
		for target in self.targets:
			yield Target(name=target, _source=self.config.name, _type='target', _context=self.context)

		# Task fmt opts
		fmt_opts = {
			'print_item_count': True,
			'print_cmd': True,
			'print_line': not self.sync,
			'print_input_file': True,
			'print_description': self.sync,
			'print_cmd_prefix': not self.sync,
			'print_timestamp': self.sync,
			'json': True
		}

		# Construct run opts
		run_opts = self.run_opts.copy()
		run_opts['hooks'] = self._hooks.get(Task, {})
		run_opts.update(fmt_opts)

		# Build Celery workflow
		workflow = self.build_celery_workflow(run_opts=run_opts, results=self.results)

		# Run Celery workflow and get results
		if self.sync:
			results = workflow.apply().get()
		else:
			result = workflow()
			results = self.process_live_tasks(result, results_only=True, print_remote_status=self.print_remote_status)

		# Get workflow results
		yield from results

	def build_celery_workflow(self, run_opts={}, results=[]):
		""""Build Celery workflow.

		Returns:
			celery.chain: Celery task chain.
		"""
		from secsy.celery import forward_results
		sigs = self.get_tasks(
			self.config.tasks.toDict(),
			self.targets,
			self.config.options,
			run_opts)
		sigs = [forward_results.si(results)] + sigs + [forward_results.s()]
		workflow = chain(*sigs)
		return workflow

	def get_tasks(self, obj, targets, workflow_opts, run_opts):
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
					run_opts
				)
				sig = chord((tasks), forward_results.s())
			elif task_name == '_chain':
				tasks = self.get_tasks(
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

				# Add task context and hooks to options
				opts['hooks'] = {task: self._hooks.get(Task, {})}
				opts['context'] = self.context.copy()
				opts['name'] = task_name

				# Create task signature
				sig = task.s(targets, **opts)
				self.output_types.extend(task.output_types)
			sigs.append(sig)
		return sigs
