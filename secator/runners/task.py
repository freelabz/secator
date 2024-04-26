from secator.definitions import DEBUG
from secator.output_types import Target
from secator.config import CONFIG
from secator.runners import Runner
from secator.utils import discover_tasks


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
		if dry_run:
			self.print_item_count = False

		# Fmt opts
		fmt_opts = {
			'json': run_opts.get('json', False),
			'print_cmd': True,
			'print_cmd_prefix': not self.sync,
			'print_input_file': DEBUG > 0,
			'print_item': True,
			'print_item_count': not self.sync and not dry_run,
			'print_line': True
			# 'print_line': self.sync and not self.output_quiet,
		}
		# self.print_item = not self.sync  # enable print_item for base Task only if running remote
		run_opts.update(fmt_opts)

		# Set task output types
		self.output_types = task_cls.output_types

		# Get hooks
		hooks = {task_cls: self.hooks}
		run_opts['hooks'] = hooks
		run_opts['context'] = self.context

		# Run task
		if self.sync:
			task = task_cls(self.targets, **run_opts)
			if dry_run:  # don't run
				return
		else:
			self.celery_result = task_cls.delay(self.targets, **run_opts)
			task = self.process_live_tasks(
				self.celery_result,
				description=False,
				results_only=True,
				print_remote_status=self.print_remote_status)

		# Yield task results
		yield from task

		# Yield targets
		for target in self.targets:
			yield Target(name=target, _source=self.config.name, _type='target', _context=self.context)

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
			if name == '_group':
				tasks.extend(Task.get_tasks_from_conf(opts))
			elif name == '_chain':
				tasks.extend(Task.get_tasks_from_conf(opts))
			else:
				if '/' in name:
					name = name.split('/')[0]
				tasks.append(name)
		return tasks
