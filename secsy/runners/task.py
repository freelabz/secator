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

	def run(self):
		return list(self.__iter__())

	def __iter__(self):
		"""Run task.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery worker in distributed mode.

		Returns:
			list: List of results.
		"""
		# Default table exporter in non-sync mode
		if not self.sync and not self.exporters:
			self.run_opts['output'] = 'table'
			self.exporters = self.resolve_exporters()

		# Overriding library defaults with CLI defaults
		table = self.run_opts.get('table', False)
		json = self.run_opts.get('json', False)
		orig = self.run_opts.get('orig', False)
		raw = self.run_opts.get('raw', False)
		fmt_opts = self.DEFAULT_FORMAT_OPTIONS.copy()
		fmt_opts.update({
			'sync': self.sync,
			'raw': raw or not (json or table or orig),
			'raw_yield': False
		})

		# In async mode, display results back in client-side
		if not self.sync:
			fmt_opts['json'] = True
			fmt_opts['print_cmd_prefix'] = True

		# Merge runtime options
		opts = merge_opts(self.run_opts, fmt_opts)

		# Get Celery task result iterator
		uuids = []
		task_cls = Task.get_task_class(self.config.name)
		if self.sync:
			task = task_cls(self.targets, **opts)
		else:
			result = task_cls.delay(self.targets, **opts)
			console.log(f'Celery task [bold magenta]{str(result)}[/] sent to broker.')
			task = self.process_live_tasks(result, description=False, results_only=True)

		# Run task and yield results
		status = f'[bold yellow]Running task [bold magenta]{self.config.name} ...'
		print_status = self.sync and (not RECORD and not task.output_json and not task.output_raw and not task.output_orig)
		with console.status(status) if print_status and self.sync else nullcontext():
			for result in task:
				if result._uuid in uuids:
					continue
				uuids.append(result._uuid)
				self.results.append(result)
				yield result

		# Filter results and log info
		self.results = self.filter_results()
		self.done = True
		self.log_results()

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
