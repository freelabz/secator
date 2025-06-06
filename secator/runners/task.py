from secator.config import CONFIG
from secator.runners import Runner
from secator.loader import discover_tasks
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
		from secator.celery import run_command

		# Get task class
		task_cls = Task.get_task_class(self.config.name)

		# Run opts
		opts = self.run_opts.copy()
		opts.pop('output', None)
		opts.pop('profiles', None)
		opts.pop('no_poll', False)

		# Set output types
		self.output_types = task_cls.output_types

		# Set hooks and reports
		self.enable_hooks = False   # Celery will handle hooks
		self.enable_reports = True  # Task will handle reports

		# Get hooks
		hooks = self._hooks.get(Task, {})
		opts['hooks'] = hooks
		opts['context'] = self.context.copy()
		opts['reports_folder'] = str(self.reports_folder)

		# Task class will handle those
		opts['enable_reports'] = False
		opts['enable_profiles'] = False
		opts['enable_duplicate_check'] = False
		opts['print_start'] = False
		opts['print_end'] = False
		opts['print_target'] = False
		opts['has_parent'] = False
		opts['skip_if_no_inputs'] = False
		opts['caller'] = 'Task'

		# Create task signature
		profile = task_cls.profile(opts) if callable(task_cls.profile) else task_cls.profile
		sig = run_command.si(self.results, self.config.name, self.inputs, opts).set(queue=profile)
		task_id = sig.freeze().task_id
		self.add_subtask(task_id, self.config.name, self.description)
		return chain(sig)

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
