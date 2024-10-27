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

		# Run task
		if self.sync:
			run_opts['print_item'] = False
			results = task_cls(self.targets, **run_opts)
			if dry_run:  # don't run
				return
		else:
			workflow = self.build_celery_workflow(run_opts=run_opts)
			self.celery_result = workflow.delay()
			results = CeleryData.iter_results(
				self.celery_result,
				ids_map=self.celery_ids_map,
				description=True,
				print_remote_info=self.print_remote_info,
				print_remote_title=f'[bold gold3]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.name}[/] results')

		# Yield task results
		yield from results

	def build_celery_workflow(self, run_opts={}):
		""""Build Celery workflow.

		Returns:
			tuple(celery.chain, List[str]): Celery task chain, Celery task ids.
		"""
		from secator.utils import debug
		run_opts = self.run_opts.copy()
		task_cls = Task.get_task_class(self.config.name)

		# Check if chunkable
		many_targets = len(self.targets) > 1
		targets_over_chunk_size = task_cls.input_chunk_size and len(self.targets) > task_cls.input_chunk_size
		has_no_file_flag = task_cls.file_flag is None
		chunk_it = many_targets and (has_no_file_flag or targets_over_chunk_size)
		self.has_children = chunk_it
		print_opts = {
			'print_cmd': True,
			'print_item': True,
			'print_line': True,
			'print_target': True
		}
		run_opts.update(print_opts)
		chunk_enabled = chunk_it and not self.sync
		debug(
			'',
			obj={
				f'{self.unique_name}': 'CHUNK STATUS',
				'chunk_enabled': chunk_enabled,
				'chunk_it': chunk_it,
				'sync': self.sync,
				'has_no_file_flag': has_no_file_flag,
				'targets_over_chunk_size': targets_over_chunk_size,
			},
			obj_after=False,
			sub='runner.celery'
		)

		# Follow multiple chunked tasks
		if chunk_enabled:
			chunk_size = 1 if has_no_file_flag else task_cls.input_chunk_size
		else:
			chunk_size = 0
		workflow = self.break_task(chunk_size)
		return workflow

	def chunker(seq, size):
		return (seq[pos:pos + size] for pos in range(0, len(seq), size))

	def break_task(self, chunk_size=1):
		"""Break a task into multiple of the same type."""
		from celery import chain, chord
		from secator.celery import forward_results
		from secator.utils import debug
		import uuid
		task_cls = Task.get_task_class(self.config.name)

		# Clone opts
		opts = self.run_opts.copy()

		# If chunk size is 0, just return the task signature
		if chunk_size == 0:
			workflow = task_cls.si(self.results, self.targets, **opts).set(queue=task_cls.profile)
			self.add_subtask(self.celery_result.id, self.config.name, self.config.description or '')
			return workflow

		# Otherwise, break targets into chunks
		chunks = self.targets
		if chunk_size > 1:
			chunks = list(Task.chunker(self.targets, chunk_size))
			self.has_children = True
		debug(
			'',
			obj={self.unique_name: 'CHUNKED', 'chunk_size': chunk_size, 'chunks': len(chunks), 'target_count': len(self.targets)},
			obj_after=False,
			sub='celery.state'
		)

		# Build signatures
		sigs = []
		for ix, chunk in enumerate(chunks):
			if not isinstance(chunk, list):
				chunk = [chunk]
			if len(chunks) > 0:  # add chunk to task opts for tracking chunks exec
				opts['chunk'] = ix + 1
				opts['chunk_count'] = len(chunks)
			task_id = str(uuid.uuid4())
			sig = task_cls.s(chunk, **opts).set(queue=task_cls.profile, task_id=task_id)
			task_name = f'{self.name}_{ix + 1}' if len(chunks) > 0 else self.name
			self.add_subtask(task_id, task_name, self.config.description or '')
			sigs.append(sig)

		# Build Celery workflow
		workflow = chain(
			forward_results.s(self.results).set(queue='io'),
			chord(
				tuple(sigs),
				forward_results.s().set(queue='io'),
			)
		)
		return workflow

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
