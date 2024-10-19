from secator.config import CONFIG
from secator.runners import Runner
from secator.utils import discover_tasks
from secator.celery_utils import CeleryData
from secator.output_types import Info


class Task(Runner):
	default_exporters = CONFIG.tasks.exporters
	enable_hooks = False

	def delay(cls, *args, **kwargs):
		from secator.celery import run_task
		return run_task.apply_async(kwargs={'args': args, 'kwargs': kwargs}, queue='celery')

	def yielder(self):
		"""Run task.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Get task class
		task_cls = Task.get_task_class(self.config.name)

		# Run opts
		run_opts = self.run_opts.copy()
		run_opts.pop('output', None)
		dry_run = run_opts.get('show', False)

		# Set task output types
		self.output_types = task_cls.output_types

		# Get hooks
		hooks = {task_cls: self.hooks}
		run_opts['hooks'] = hooks
		run_opts['context'] = self.context

		# Run task
		if self.sync:
			run_opts['print_item'] = False
			results = task_cls(self.targets, **run_opts)
			if dry_run:  # don't run
				return
		else:
			self.celery_result = task_cls.delay(self.targets, **run_opts)
			yield Info(
				message=f'Celery task created: {self.celery_result.id}',
				task_id=self.celery_result.id
			)
			results = CeleryData.iter_results(
				self.celery_result,
				description=True,
				print_remote_info=self.print_remote_info,
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

	@staticmethod
	def get_tasks_from_conf(config):
		"""Get task names from config. Ignore hierarchy and keywords.

		TODO: Add hierarchy tree / add make flow diagrams.
		"""
		tasks = []
		for name, opts in config.items():
			if name.startswith('_group'):
				tasks.extend(Task.get_tasks_from_conf(opts))
			elif name == '_chain':
				tasks.extend(Task.get_tasks_from_conf(opts))
			else:
				if '/' in name:
					name = name.split('/')[0]
				tasks.append(name)
		return tasks
