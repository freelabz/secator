from secator.definitions import DEBUG
from secator.output_types import Target
from secator.runners import Runner
from secator.utils import discover_tasks


class Task(Runner):
	default_exporters = []
	enable_hooks = False

	def delay(cls, *args, **kwargs):
		from secator.celery import run_task
		return run_task.delay(args=args, kwargs=kwargs)

	def yielder(self):
		"""Run task.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Get task class
		task_cls = Task.get_task_class(self.config.name)

		# Task opts
		run_opts = self.run_opts.copy()
		run_opts.pop('output', None)

		# Fmt opts
		fmt_opts = {
			'print_cmd': True,
			'print_cmd_prefix': not self.sync,
			'print_line': not self.output_quiet,
			'print_item_count': not self.sync,
			'print_input_file': DEBUG
		}
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
		else:
			result = task_cls.delay(self.targets, **run_opts)
			task = self.process_live_tasks(result, description=False, results_only=True)

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