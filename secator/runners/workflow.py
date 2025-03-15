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

	def build_celery_workflow(self):
		"""Build Celery workflow for workflow execution.

		Returns:
			celery.Signature: Celery task signature.
		"""
		from celery import chain
		from secator.celery import mark_runner_started, mark_runner_complete

		# Prepare run options
		opts = self.run_opts.copy()
		opts['hooks'] = self._hooks.get(Task, {})
		opts.pop('no_poll', False)

		# Build task signatures
		sigs = self.get_tasks(
			self.config.tasks.toDict(),
			self.inputs,
			self.config.options,
			opts)

		# Build workflow chain with lifecycle management
		return chain(
			mark_runner_started.si(self).set(queue='results'),
			*sigs,
			mark_runner_complete.s(self).set(queue='results'),
		)

	def get_tasks(self, config, inputs, workflow_opts, run_opts):
		"""Get tasks recursively as Celery chains / chords.

		Args:
			config (dict): Tasks config dict.
			inputs (list): Inputs.
			workflow_opts (dict): Workflow options.
			run_opts (dict): Run options.
			sync (bool): Synchronous mode (chain of tasks, no chords).

		Returns:
			tuple (List[celery.Signature], List[str]): Celery signatures, Celery task ids.
		"""
		from celery import chain, chord
		from secator.celery import forward_results
		sigs = []
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
				sig = chord((tasks), forward_results.s().set(queue='results'))
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

				# Add task context and hooks to options
				opts['hooks'] = {task: self._hooks.get(Task, {})}
				opts['context'] = self.context.copy()
				opts['name'] = task_name
				opts['has_parent'] = True
				opts['skip_if_no_inputs'] = True

				# Create task signature
				task_id = str(uuid.uuid4())
				sig = task.s(inputs, **opts).set(queue=task.profile, task_id=task_id)
				self.add_subtask(task_id, task_name, task_opts.get('description', ''))
				self.output_types.extend(task.output_types)
			sigs.append(sig)
		return sigs
