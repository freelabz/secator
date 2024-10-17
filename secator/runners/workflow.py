from secator.config import CONFIG
from secator.runners._base import Runner
from secator.runners.task import Task
from secator.utils import merge_opts
from secator.celery_utils import CeleryData


class Workflow(Runner):

	default_exporters = CONFIG.workflows.exporters

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_workflow
		return run_workflow.delay(args=args, kwargs=kwargs)

	def yielder(self):
		"""Run workflow.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Task opts
		run_opts = self.run_opts.copy()
		run_opts['hooks'] = self._hooks.get(Task, {})

		# Build Celery workflow
		workflow = self.build_celery_workflow(
			run_opts=run_opts,
			results=self.results
		)

		# Run Celery workflow and get results
		if self.sync:
			results = workflow.apply().get()
		else:
			result = workflow()
			self.celery_result = result
			results = CeleryData.iter_results(
				self.celery_result,
				description=True,
				results_only=True,
				print_remote_info=self.print_remote_info,
				print_remote_title=f'[bold gold3]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.name}[/] results'
			)

		# Get workflow results
		yield from results

	def build_celery_workflow(self, run_opts={}, results=[]):
		""""Build Celery workflow.

		Returns:
			celery.chain: Celery task chain.
		"""
		from celery import chain
		from secator.celery import forward_results
		sigs = self.get_tasks(
			self.config.tasks.toDict(),
			self.targets,
			self.config.options,
			run_opts)
		sigs = [forward_results.si(results).set(queue='io')] + sigs + [forward_results.s().set(queue='io')]
		workflow = chain(*sigs)
		return workflow

	def get_tasks(self, obj, targets, workflow_opts, run_opts):
		"""Get tasks recursively as Celery chains / chords.

		Args:
			obj (secator.config.TemplateLoader): Config.
			targets (list): List of targets.
			workflow_opts (dict): Workflow options.
			run_opts (dict): Run options.
			sync (bool): Synchronous mode (chain of tasks, no chords).

		Returns:
			list: List of signatures.
		"""
		from celery import chain, chord
		from secator.celery import forward_results
		sigs = []
		for task_name, task_opts in obj.items():
			# Task opts can be None
			task_opts = task_opts or {}

			# If it's a group, process the sublevel tasks as a Celery chord.
			if task_name.startswith('_group'):
				tasks = self.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts
				)
				sig = chord((tasks), forward_results.s().set(queue='io'))
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
				sig = task.s(targets, **opts).set(queue=task.profile)
				self.output_types.extend(task.output_types)
			sigs.append(sig)
		return sigs
