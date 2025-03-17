import uuid
from secator.config import CONFIG
from secator.runners import Runner
from secator.utils import discover_tasks
from celery import chain


class Task(Runner):

	default_exporters = CONFIG.tasks.exporters

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_task
		return run_task.apply_async(kwargs={'args': args, 'kwargs': kwargs}, queue='celery')

	def build_celery_workflow(self):
		"""Build Celery workflow for task execution.

		Args:
			run_opts (dict): Run options.
			results (list): Prior results.

		Returns:
			celery.Signature: Celery task signature.
		"""
		from secator.celery import run_command, mark_runner_started, mark_runner_complete

		# Get task class
		task_cls = Task.get_task_class(self.config.name)

		# Run opts
		opts = self.run_opts.copy()
		opts.pop('output', None)
		opts.pop('no_poll', False)

		# Set task output types
		self.output_types = task_cls.output_types
		self.enable_duplicate_check = False
		self.enable_hooks = False

		# Get hooks
		hooks = self._hooks.get(Task, {})
		opts['hooks'] = hooks
		opts['context'] = self.context

		# Create task signature
		task_id = str(uuid.uuid4())
		sig = run_command.s(self.config.name, self.inputs, opts).set(queue=task_cls.profile, task_id=task_id)
		self.add_subtask(task_id, self.config.name, self.config.description or '')

		# Build signature chain with lifecycle management
		return chain(
			mark_runner_started.si(self).set(queue='results'),
			sig,
			mark_runner_complete.s(self).set(queue='results'),
		)

	@staticmethod
	def get_task_class(name):
		"""Get task class from a name.

		Args:
			name (str): Task name.
		"""
		if '/' in name:
			name = name.split('/')[0]
		tasks_classes = discover_tasks()
		for task_cls in tasks_classes:
			if task_cls.__name__ == name:
				return task_cls
		raise ValueError(f'Task {name} not found. Aborting.')
