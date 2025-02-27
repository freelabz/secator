from secator.config import CONFIG
from secator.runners import Runner
from secator.utils import discover_tasks
from secator.celery_utils import CeleryData
from secator.output_types import Info


class Task(Runner):
	default_exporters = CONFIG.tasks.exporters
	enable_hooks = False

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_task
		return run_task.apply_async(kwargs={'args': args, 'kwargs': kwargs}, queue='celery')

	def yielder(self):
		"""Run task.

		Yields:
			secator.output_types.OutputType: Secator output type.
		"""
		# Get task class
		task_cls = Task.get_task_class(self.config.name)

		# Run opts
		run_opts = self.run_opts.copy()
		run_opts.pop('output', None)
		run_opts.pop('no_poll', False)

		# Set task output types
		self.output_types = task_cls.output_types
		self.enable_duplicate_check = False

		# Get hooks
		hooks = {task_cls: self.hooks}
		run_opts['hooks'] = hooks
		run_opts['context'] = self.context

		# Run task
		if self.sync:
			self.print_item = False
			result = task_cls.si(self.inputs, **run_opts)
			results = result.apply().get()
		else:
			self.celery_result = task_cls.delay(self.inputs, **run_opts)
			self.add_subtask(self.celery_result.id, self.config.name, self.config.description or '')
			yield Info(
				message=f'Celery task created: {self.celery_result.id}',
				task_id=self.celery_result.id
			)
			if self.no_poll:
				return
			results = CeleryData.iter_results(
				self.celery_result,
				ids_map=self.celery_ids_map,
				description=True,
				print_remote_info=False,
				print_remote_title=f'[bold gold3]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.name}[/] results')

		# Yield task results
		yield from results

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
