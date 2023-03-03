from contextlib import nullcontext

import yaml

from secsy.rich import console
from secsy.runners._base import Runner
from secsy.runners._helpers import confirm_exit
from secsy.utils import discover_tasks, merge_opts


class Task(Runner):

	_print_table = False
	_save_html = False

	@confirm_exit
	def run(self, sync=True):
		"""Run task.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery 
				worker in distributed mode.

		Returns:
			list: List of results.
		"""
		table = self.run_opts.pop('table', False)
		json = self.run_opts.get('json', False)
		self._print_table = table or not sync
		self.sync = sync
		fmt_opts = {
			'print_timestamp': True,
			'print_cmd': True,
			'print_cmd_prefix': not sync,
			'print_item_count': True,
			'print_line': True,
			'sync': sync,
			'json': json or not sync,
			'track': True
		}
		opts = merge_opts(self.run_opts, fmt_opts)

		# Run Celery workflow and get results
		task_cls = Task.get_task_class(self.config.name)
		if sync:
			task = task_cls(self.targets, **opts)
			with console.status(f'[bold yellow]Running task [bold magenta]{self.config.name} ...') if not task._json_output and not task._raw_output and not task._orig_output else nullcontext():
				self.results = task.run()
		else:
			result = task_cls.delay(self.targets, **opts)
			console.log(f'Celery task [bold magenta]{str(result)}[/] sent to broker.')
			self.process_live_tasks(result)
			self.results = result.get(propagate=False)
			self.results = self.results['results'] if isinstance(self.results, dict) else self.results
		if opts.get('debug', False):
			console.log(yaml.dump(self.results))
		self.results = self.filter_results()
		self.log_results()
		self.done = True
		return self.results

	@staticmethod
	def get_task_class(name):
		"""Get task class from a name.
		
		Args:
			name (str): Task name.
		"""
		tasks_classes = discover_tasks()
		for task_cls in tasks_classes:
			if task_cls.__name__ == name:
				return task_cls
		console.log(
			f'Task {name} not found. Aborting.', style='bold red')
		return None

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
				tasks.append(name)
		return tasks