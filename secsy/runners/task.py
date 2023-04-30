from contextlib import nullcontext

from secsy.definitions import RECORD
from secsy.rich import console
from secsy.utils import discover_tasks, merge_opts
from secsy.runners import Runner


class Task(Runner):
	DEFAULT_EXPORTERS = []
	DEFAULT_FORMAT_OPTIONS = {
		'print_timestamp': True,
		'print_cmd': True,
		'print_line': True,
		'raw_yield': False
	}

	def delay(cls, *args, **kwargs):
		from secsy.celery import run_task
		return run_task.delay(args=args, kwargs=kwargs)

	def __iter__(self):
		"""Run task.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Get Celery task result iterator
		task_cls = Task.get_task_class(self.config.name)
		if self.sync:
			task = task_cls(self.targets, **self.run_opts)
		else:
			result = task_cls.delay(self.targets, **self.run_opts)
			console.log(f'Celery task [bold magenta]{str(result)}[/] sent to broker.')
			task = self.process_live_tasks(result, description=False, results_only=True)

		# Run task and yield results
		status = f'[bold yellow]Running task [bold magenta]{self.config.name} ...'
		print_status = self.sync and (not RECORD and not task.output_json and not task.output_raw and not task.output_orig)
		with console.status(status) if print_status and self.sync else nullcontext():
			yield from task

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
