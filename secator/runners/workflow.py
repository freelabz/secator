import uuid

from secator.config import CONFIG
from secator.runners._base import Runner
from secator.runners.task import Task
from secator.utils import merge_opts


class Workflow(Runner):

	default_exporters = CONFIG.workflows.exporters

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_workflow
		return run_workflow.delay(args=args, kwargs=kwargs)

	@classmethod
	def s(cls, *args, **kwargs):
		from secator.celery import run_workflow
		return run_workflow.s(args=args, kwargs=kwargs)

	def build_celery_workflow(self, chain_previous_results=False):
		"""Build Celery workflow for workflow execution.

		Args:
			chain_previous_results (bool): Chain previous results.

		Returns:
			celery.Signature: Celery task signature.
		"""
		from celery import chain
		from secator.celery import mark_runner_started, mark_runner_completed

		# Prepare run options
		opts = self.run_opts.copy()
		opts.pop('output', None)
		opts.pop('no_poll', False)

		# Set hooks and reports
		self.enable_reports = True  # Workflow will handle reports
		self.enable_hooks = False   # Celery will handle hooks

		# Get hooks
		hooks = self._hooks.get(Task, {})
		opts['hooks'] = hooks
		opts['context'] = self.context.copy()
		opts['reports_folder'] = str(self.reports_folder)
		opts['enable_reports'] = False  # Workflow will handle reports
		opts['enable_duplicate_check'] = False  # Workflow will handle duplicate check
		opts['has_parent'] = True
		opts['skip_if_no_inputs'] = True
		opts['caller'] = 'Workflow'

		forwarded_opts = {}
		if chain_previous_results:
			forwarded_opts = {k: v for k, v in self.run_opts.items() if k.endswith('_')}

		# Build task signatures
		sigs = self.get_tasks(
			self.config.tasks.toDict(),
			self.inputs,
			self.config.options,
			opts,
			forwarded_opts=forwarded_opts
		)

		start_sig = mark_runner_started.si([], self, enable_hooks=True).set(queue='results')
		if chain_previous_results:
			start_sig = mark_runner_started.s(self, enable_hooks=True).set(queue='results')

		# Build workflow chain with lifecycle management
		return chain(
			start_sig,
			*sigs,
			mark_runner_completed.s(self, enable_hooks=True).set(queue='results'),
		)

	def get_tasks(self, config, inputs, workflow_opts, run_opts, forwarded_opts={}):
		"""Get tasks recursively as Celery chains / chords.

		Args:
			config (dict): Tasks config dict.
			inputs (list): Inputs.
			workflow_opts (dict): Workflow options.
			run_opts (dict): Run options.
			forwarded_opts (dict): Opts forwarded from parent runner (e.g: scan).
			sync (bool): Synchronous mode (chain of tasks, no chords).

		Returns:
			tuple (List[celery.Signature], List[str]): Celery signatures, Celery task ids.
		"""
		from celery import chain, group
		sigs = []
		ix = 0
		for task_name, task_opts in config.items():
			# Task opts can be None
			task_opts = task_opts or {}

			# If it's a group, process the sublevel tasks as a Celery chord.
			if task_name.startswith('_group'):
				tasks = self.get_tasks(
					task_opts,
					inputs,
					workflow_opts,
					run_opts
				)
				sig = group(*tasks)
			elif task_name == '_chain':
				tasks = self.get_tasks(
					task_opts,
					inputs,
					workflow_opts,
					run_opts
				)
				sig = chain(*tasks)
			else:
				# Get task class
				task = Task.get_task_class(task_name)

				# Merge task options (order of priority with overrides)
				opts = merge_opts(workflow_opts, task_opts, run_opts)
				if ix == 0 and forwarded_opts:
					opts.update(forwarded_opts)
				opts['name'] = task_name

				# Create task signature
				task_id = str(uuid.uuid4())
				opts['context'] = self.context.copy()
				sig = task.s(inputs, **opts).set(queue=task.profile, task_id=task_id)
				self.add_subtask(task_id, task_name, task_opts.get('description', ''))
				self.output_types.extend(task.output_types)
				ix += 1
			sigs.append(sig)
		return sigs
