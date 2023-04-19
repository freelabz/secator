from contextlib import nullcontext

from secsy.definitions import RECORD
from secsy.rich import console
from secsy.runners._base import Runner
from secsy.utils import discover_tasks, merge_opts


class Task(Runner):

	DEFAULT_EXPORTERS = []
	DEFAULT_FORMAT_OPTIONS = {
		'print_timestamp': True,
		'print_cmd': True,
		'print_line': True,
		'raw_yield': False
	}

	def run(self, sync=True):
		"""Run task.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		self.sync = sync

		# Overriding library defaults with CLI defaults
		table = self.run_opts.get('table', False)
		json = self.run_opts.get('json', False)
		orig = self.run_opts.get('orig', False)
		raw = self.run_opts.get('raw', False)
		fmt_opts = self.DEFAULT_FORMAT_OPTIONS.copy()
		fmt_opts.update({
			'sync': sync,
			'raw': raw or not (json or table or orig),
			'raw_yield': False
		})

		# In async mode, display results back in client-side
		if not sync:
			fmt_opts['json'] = True
			fmt_opts['print_cmd_prefix'] = True

		# Merge runtime options
		opts = merge_opts(self.run_opts, fmt_opts)

		# Run Celery workflow and get results
		task_cls = Task.get_task_class(self.config.name)
		if sync:
			task = task_cls(self.targets, **opts)
			print_status = not RECORD and not task.output_json and not task.output_raw and not task.output_orig
			status = f'[bold yellow]Running task [bold magenta]{self.config.name} ...'
			with console.status(status) if print_status else nullcontext():
				self.results = task.run()
		else:
			result = task_cls.delay(self.targets, **opts)
			console.log(f'Celery task [bold magenta]{str(result)}[/] sent to broker.')
			list(self.process_live_tasks(result))
			self.results = result.get()
			self.results = self.results['results']
		self.results = self.filter_results()
		self.done = True
		self.log_results()
		return self.results

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
		raise ValueError(
			f'Task {name} not found. Aborting.', style='bold red'
		)

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
