import gc
import json
import logging
import sys
import textwrap
import uuid

from datetime import datetime
from pathlib import Path
from time import time

from dotmap import DotMap
import humanize

from secator.definitions import ADDONS_ENABLED, STATE_COLORS
from secator.celery_utils import CeleryData
from secator.config import CONFIG
from secator.output_types import FINDING_TYPES, OUTPUT_TYPES, OutputType, Progress, Info, Warning, Error, Target, State
from secator.report import Report
from secator.rich import console, console_stdout
from secator.runners._helpers import (get_task_folder_id, run_extractors)
from secator.utils import (debug, import_dynamic, rich_to_ansi, should_update, autodetect_type)
from secator.tree import build_runner_tree
from secator.loader import get_configs_by_type


logger = logging.getLogger(__name__)

HOOKS = [
	'before_init',
	'on_init',
	'on_start',
	'on_end',
	'on_item_pre_convert',
	'on_item',
	'on_duplicate',
	'on_interval',
]

VALIDATORS = [
	'validate_input',
	'validate_item'
]


def format_runner_name(runner):
	"""Format runner name."""
	colors = {
		'task': 'bold gold3',
		'workflow': 'bold dark_orange3',
		'scan': 'bold red',
	}
	return f'[{colors[runner.config.type]}]{runner.unique_name}[/]'


class Runner:
	"""Runner class.

	Args:
		config (secator.config.TemplateLoader): Runner config.
		inputs (List[str]): List of inputs to run task on.
		results (List[OutputType]): List of results to re-use.
		run_opts (dict[str]): Run options.
		hooks (dict[str, List[Callable]]): User hooks to register.
		validators (dict): User validators to register.
		context (dict): Runner context.

	Yields:
		OutputType: Output types.
	"""

	# Input field (mostly for tests and CLI)
	input_types = []

	# Output types
	output_types = []

	# Default exporters
	default_exporters = []

	# Profiles
	profiles = []

	# Run hooks
	enable_hooks = True

	def __init__(self, config, inputs=[], results=[], run_opts={}, hooks={}, validators={}, context={}):
		# Runner config
		self.config = DotMap(config.toDict())
		self.name = run_opts.get('name', config.name)
		self.description = run_opts.get('description', config.description or '')
		self.workspace_name = context.get('workspace_name', 'default')
		self.run_opts = run_opts.copy()
		self.sync = run_opts.get('sync', True)
		self.context = context

		# Runner state
		self.uuids = set()
		self.results = []
		self.results_count = 0
		self.threads = []
		self.output = ''
		self.started = False
		self.done = False
		self.start_time = datetime.fromtimestamp(time())
		self.end_time = None
		self.last_updated_db = None
		self.last_updated_celery = None
		self.last_updated_progress = None
		self.progress = 0
		self.celery_result = None
		self.celery_ids = []
		self.celery_ids_map = {}
		self.revoked = False
		self.results_buffer = []
		self._hooks = hooks

		# Runner process options
		self.no_poll = self.run_opts.get('no_poll', False)
		self.no_process = not self.run_opts.get('process', True)
		self.piped_input = self.run_opts.get('piped_input', False)
		self.piped_output = self.run_opts.get('piped_output', False)
		self.dry_run = self.run_opts.get('dry_run', False)
		self.has_parent = self.run_opts.get('has_parent', False)
		self.has_children = self.run_opts.get('has_children', False)
		self.caller = self.run_opts.get('caller', None)
		self.quiet = self.run_opts.get('quiet', False)
		self._reports_folder = self.run_opts.get('reports_folder', None)
		self.raise_on_error = self.run_opts.get('raise_on_error', False)

		# Runner toggles
		self.enable_duplicate_check = self.run_opts.get('enable_duplicate_check', True)
		self.enable_profiles = self.run_opts.get('enable_profiles', True)
		self.enable_reports = self.run_opts.get('enable_reports', not self.sync) and not self.dry_run and not self.no_process and not self.no_poll  # noqa: E501
		self.enable_hooks = self.run_opts.get('enable_hooks', True) and not self.dry_run and not self.no_process  # noqa: E501

		# Runner print opts
		self.print_item = self.run_opts.get('print_item', False) and not self.dry_run
		self.print_line = self.run_opts.get('print_line', False) and not self.quiet
		self.print_remote_info = self.run_opts.get('print_remote_info', False) and not self.piped_input and not self.piped_output  # noqa: E501
		self.print_start = self.run_opts.get('print_start', False) and not self.dry_run  # noqa: E501
		self.print_end = self.run_opts.get('print_end', False) and not self.dry_run  # noqa: E501
		self.print_target = self.run_opts.get('print_target', False) and not self.dry_run and not self.has_parent
		self.print_json = self.run_opts.get('print_json', False)
		self.print_raw = self.run_opts.get('print_raw', False) or (self.piped_output and not self.print_json)
		self.print_fmt = self.run_opts.get('fmt', '')
		self.print_stat = self.run_opts.get('print_stat', False)
		self.print_profiles = self.run_opts.get('print_profiles', False)

		# Chunks
		self.chunk = self.run_opts.get('chunk', None)
		self.chunk_count = self.run_opts.get('chunk_count', None)
		self.unique_name = self.name.replace('/', '_')
		self.unique_name = f'{self.unique_name}_{self.chunk}' if self.chunk else self.unique_name

		# Opt aliases
		self.opt_aliases = []
		if self.config.node_id:
			self.opt_aliases.append(self.config.node_id.replace('.', '_'))
		if self.config.node_name:
			self.opt_aliases.append(self.config.node_name)
		self.opt_aliases.append(self.unique_name)

		# Begin initialization
		self.debug(f'begin initialization of {self.unique_name}', sub='init')

		# Hooks
		self.resolved_hooks = {name: [] for name in HOOKS + getattr(self, 'hooks', [])}
		self.debug('registering hooks', obj=list(self.resolved_hooks.keys()), sub='init')
		self.register_hooks(hooks)

		# Validators
		self.resolved_validators = {name: [] for name in VALIDATORS + getattr(self, 'validators', [])}
		self.debug('registering validators', obj={'validators': list(self.resolved_validators.keys())}, sub='init')
		self.resolved_validators['validate_input'].append(self._validate_inputs)
		self.register_validators(validators)

		# Add prior results to runner results
		self.debug(f'adding {len(results)} prior results to runner', sub='init')
		for result in results:
			self.add_result(result, print=False, output=False, hooks=False, queue=not self.has_parent)

		# Determine inputs
		self.debug(f'resolving inputs with dynamic opts ({len(self.dynamic_opts)})', obj=self.dynamic_opts, sub='init')
		self.inputs = [inputs] if not isinstance(inputs, list) else inputs
		self.inputs = list(set(self.inputs))
		targets = [Target(name=target) for target in self.inputs]
		for target in targets:
			self.add_result(target, print=False, output=False)

		# Run extractors on results and targets
		self._run_extractors(results + targets)
		self.debug(f'inputs ({len(self.inputs)})', obj=self.inputs, sub='init')
		self.debug(f'run opts ({len(self.resolved_opts)})', obj=self.resolved_opts, sub='init')
		self.debug(f'print opts ({len(self.resolved_print_opts)})', obj=self.resolved_print_opts, sub='init')

		# Load profiles
		profiles_str = run_opts.get('profiles') or []
		self.debug('resolving profiles', obj={'profiles': profiles_str}, sub='init')
		self.profiles = self.resolve_profiles(profiles_str)

		# Determine exporters
		exporters_str = self.run_opts.get('output') or self.default_exporters
		self.debug('resolving exporters', obj={'exporters': exporters_str}, sub='init')
		self.exporters = self.resolve_exporters(exporters_str)

		# Profiler
		self.enable_pyinstrument = self.run_opts.get('enable_pyinstrument', False) and ADDONS_ENABLED['trace']
		if self.enable_pyinstrument:
			self.debug('enabling profiler', sub='init')
			from pyinstrument import Profiler
			self.profiler = Profiler(async_mode=False, interval=0.0001)
			try:
				self.profiler.start()
			except RuntimeError:
				self.enable_pyinstrument = False
				pass

		# Input post-process
		self.run_hooks('before_init', sub='init')

		# Check if input is valid
		self.inputs_valid = self.run_validators('validate_input', self.inputs, sub='init')

		# Print targets
		if self.print_target:
			pluralize = 'targets' if len(self.self_targets) > 1 else 'target'
			self._print(Info(message=f'Loaded {len(self.self_targets)} {pluralize} for {format_runner_name(self)}:'), rich=True)
			for target in self.self_targets:
				self._print(f'      {repr(target)}', rich=True)

		# Run hooks
		self.run_hooks('on_init', sub='init')

	@property
	def resolved_opts(self):
		return {k: v for k, v in self.run_opts.items() if v is not None and not k.startswith('print_') and not k.endswith('_')}  # noqa: E501

	@property
	def resolved_print_opts(self):
		return {k: v for k, v in self.__dict__.items() if k.startswith('print_') if v}

	@property
	def dynamic_opts(self):
		return {k: v for k, v in self.run_opts.items() if k.endswith('_')}

	@property
	def elapsed(self):
		if self.done:
			return self.end_time - self.start_time
		return datetime.fromtimestamp(time()) - self.start_time

	@property
	def elapsed_human(self):
		return humanize.naturaldelta(self.elapsed)

	@property
	def targets(self):
		return [r for r in self.results if isinstance(r, Target)]

	@property
	def self_targets(self):
		return [r for r in self.results if isinstance(r, Target) and r._source.startswith(self.unique_name)]

	@property
	def infos(self):
		return [r for r in self.results if isinstance(r, Info)]

	@property
	def warnings(self):
		return [r for r in self.results if isinstance(r, Warning)]

	@property
	def errors(self):
		return [r for r in self.results if isinstance(r, Error)]

	@property
	def self_results(self):
		return [r for r in self.results if r._source.startswith(self.unique_name)]

	@property
	def findings(self):
		return [r for r in self.results if isinstance(r, tuple(FINDING_TYPES))]

	@property
	def findings_count(self):
		return len(self.findings)

	@property
	def self_findings(self):
		return [r for r in self.results if isinstance(r, tuple(FINDING_TYPES)) if r._source.startswith(self.unique_name)]

	@property
	def self_errors(self):
		if self.config.type == 'task':
			return [r for r in self.results if isinstance(r, Error) and r._source.startswith(self.unique_name)]
		return [r for r in self.results if isinstance(r, Error)]

	@property
	def self_findings_count(self):
		return len(self.self_findings)

	@property
	def status(self):
		if not self.started:
			return 'PENDING'
		if self.revoked:
			return 'REVOKED'
		if not self.done:
			return 'RUNNING'
		return 'FAILURE' if len(self.self_errors) > 0 else 'SUCCESS'

	@property
	def celery_state(self):
		return {
			'name': self.config.name,
			'full_name': self.unique_name,
			'state': self.status,
			'progress': self.progress,
			'results': self.self_results,
			'chunk': self.chunk,
			'chunk_count': self.chunk_count,
			'chunk_info': f'{self.chunk}/{self.chunk_count}' if self.chunk and self.chunk_count else '',
			'celery_id': self.context['celery_id'],
			'count': self.self_findings_count,
			'descr': self.description
		}

	@property
	def reports_folder(self):
		if self._reports_folder and Path(self._reports_folder).exists():
			return self._reports_folder
		_base = f'{CONFIG.dirs.reports}/{self.workspace_name}/{self.config.type}s'
		_id = get_task_folder_id(_base)
		path = Path(f'{_base}/{_id}')
		path_inputs = path / '.inputs'
		path_outputs = path / '.outputs'
		if not path.exists():
			self.debug(f'creating reports folder {path}', sub='start')
			path.mkdir(parents=True, exist_ok=True)
			path_inputs.mkdir(exist_ok=True)
			path_outputs.mkdir(exist_ok=True)
		self._reports_folder = path.resolve()
		return self._reports_folder

	@property
	def id(self):
		"""Get id from context.

		Returns:
			str: Id.
		"""
		return self.context.get('task_id', '') or self.context.get('workflow_id', '') or self.context.get('scan_id', '')

	@property
	def ancestor_id(self):
		"""Get ancestor id from context.

		Returns:
			str: Ancestor id.
		"""
		return self.context.get('ancestor_id')

	def run(self):
		"""Run method.

		Returns:
			List[OutputType]: List of runner results.
		"""
		return list(self.__iter__())

	def __iter__(self):
		"""Process results from derived runner class in real-time and yield results.

		Yields:
			OutputType: runner result.
		"""
		try:
			# If sync mode, set started
			if self.sync:
				self.mark_started()

			# Yield results buffer
			yield from self.results_buffer
			self.results_buffer = []

			# If any errors happened during validation, exit
			if self.self_errors:
				self._finalize()
				return

			# Loop and process items
			for item in self.yielder():
				yield from self._process_item(item)
				self.run_hooks('on_interval', sub='item')

		except BaseException as e:
			self.debug(f'encountered exception {type(e).__name__}. Stopping remote tasks.', sub='run')
			error = Error.from_exception(e)
			self.add_result(error)
			self.revoked = True
			if not self.sync:  # yield latest results from Celery
				self.stop_celery_tasks()
				for item in self.yielder():
					yield from self._process_item(item)
					self.run_hooks('on_interval', sub='item')

		finally:
			yield from self.results_buffer
			self.results_buffer = []
			self._finalize()

	def _finalize(self):
		"""Finalize the runner."""
		self.join_threads()
		gc.collect()
		if self.sync:
			self.mark_completed()
		if self.enable_reports:
			self.export_reports()

	def join_threads(self):
		"""Wait for all running threads to complete."""
		if not self.threads:
			return
		self.debug(f'waiting for {len(self.threads)} threads to complete', sub='end')
		for thread in self.threads:
			error = thread.join()
			if error:
				self.add_result(error)

	def _run_extractors(self, results):
		"""Run extractors on results and targets."""
		self.debug('running extractors', sub='init')
		ctx = {'opts': DotMap(self.run_opts), 'targets': self.inputs, 'ancestor_id': self.ancestor_id}
		inputs, run_opts, errors = run_extractors(
			results,
			self.run_opts,
			self.inputs,
			ctx=ctx,
			dry_run=self.dry_run)
		for error in errors:
			self.add_result(error)
		self.inputs = sorted(list(set(inputs)))
		self.debug(f'extracted {len(self.inputs)} inputs', sub='init')
		self.run_opts = run_opts

	def add_result(self, item, print=True, output=True, hooks=True, queue=True):
		"""Add item to runner results.

		Args:
			item (OutputType): Item.
			print (bool): Whether to print it or not.
			output (bool): Whether to add it to the output or not.
			hooks (bool): Whether to run hooks on the item.
			queue (bool): Whether to queue the item for later processing.
		"""
		if item._uuid and item._uuid in self.uuids:
			return

		# Keep existing ancestor id in context
		ancestor_id = item._context.get('ancestor_id', None)

		# Set context
		item._context.update(self.context)
		item._context['ancestor_id'] = ancestor_id or self.ancestor_id

		# Set uuid
		if not item._uuid:
			item._uuid = str(uuid.uuid4())

		# Set source
		if not item._source:
			item._source = self.unique_name

		# Check for state updates
		if isinstance(item, State) and self.celery_result and item.task_id == self.celery_result.id:
			self.debug(f'update runner state from remote state: {item.state}', sub='item')
			if item.state in ['FAILURE', 'SUCCESS', 'REVOKED']:
				self.started = True
				self.done = True
				self.progress = 100
				self.end_time = datetime.fromtimestamp(time())
			elif item.state in ['RUNNING']:
				self.started = True
				self.start_time = datetime.fromtimestamp(time())
				self.end_time = None
			self.last_updated_celery = item._timestamp
			return

		# If progress item, update runner progress
		elif isinstance(item, Progress) and item._source == self.unique_name:
			self.debug(f'update runner progress: {item.percent}', sub='item', verbose=True)
			if not should_update(CONFIG.runners.progress_update_frequency, self.last_updated_progress, item._timestamp):
				return
			self.progress = item.percent
			self.last_updated_progress = item._timestamp

		# If info item and task_id is defined, update runner celery_ids
		elif isinstance(item, Info) and item.task_id and item.task_id not in self.celery_ids:
			self.debug(f'update runner celery_ids from remote: {item.task_id}', sub='item')
			self.celery_ids.append(item.task_id)

		# If output type, run on_item hooks
		elif isinstance(item, tuple(OUTPUT_TYPES)) and hooks:
			item = self.run_hooks('on_item', item, sub='item')
			if not item:
				return

		# Add item to results
		self.uuids.add(item._uuid)
		self.results.append(item)
		self.results_count += 1
		if output:
			self.output += repr(item) + '\n'
		if print:
			self._print_item(item)
		if queue:
			self.results_buffer.append(item)

	def add_subtask(self, task_id, task_name, task_description):
		"""Add a Celery subtask to the current runner for tracking purposes.

		Args:
			task_id (str): Celery task id.
			task_name (str): Task name.
			task_description (str): Task description.
		"""
		self.celery_ids.append(task_id)
		self.celery_ids_map[task_id] = {
			'id': task_id,
			'name': task_name,
			'full_name': task_name,
			'descr': task_description,
			'state': 'PENDING',
			'count': 0,
			'progress': 0
		}

	def _print_item(self, item, force=False):
		"""Print an item and add it to the runner's output.

		Args:
			item (str | OutputType): Secator output type to print.
			force (bool): Whether to force-print it.
		"""
		item_str = str(item)

		# Item is an output type
		if isinstance(item, OutputType):
			_type = item._type
			print_this_type = getattr(self, f'print_{_type}', True)
			self.debug(item, lazy=lambda x: repr(x), sub='item', allow_no_process=False, verbose=print_this_type)
			if not print_this_type:
				return

			if self.print_item or force:
				item_out = sys.stdout

				# JSON lines output
				if self.print_json:
					self._print(item, out=sys.stdout)
					item_out = None  # suppress item repr output to sdout

				# Raw output
				elif self.print_raw:
					item_out = sys.stderr if self.piped_output else None

					# Format raw output with custom item fields
					if self.print_fmt:
						try:
							item_str = item.format(**self.print_fmt)
						except KeyError:
							item_str = ''

					# raw output is used to pipe, we should only pipe the first output type of a Runner.
					if not isinstance(item, self.output_types[0]):
						item_str = ''

					if item_str:
						self._print(item_str, out=sys.stdout)

				# Repr output
				if item_out:
					item_repr = repr(item)
					if self.print_remote_info and item._source:
						item_repr += rich_to_ansi(rf' \[[dim]{item._source}[/]]')
					# item_repr += f' ({self.__class__.__name__}) ({item._uuid}) ({item._context.get("ancestor_id")})'  # for debugging
					self._print(item_repr, out=item_out)

		# Item is a line
		elif isinstance(item, str):
			self.debug(item, sub='line.print', allow_no_process=False, verbose=True)
			if self.print_line or force:
				self._print(item, out=sys.stderr, end='\n', rich=False)

	def debug(self, *args, **kwargs):
		"""Print debug with runner class name, only if self.no_process is True.

		Args:
			args (list): List of debug args.
			kwargs (dict): Dict of debug kwargs.
		"""
		allow_no_process = kwargs.pop('allow_no_process', True)
		if self.no_process and not allow_no_process:
			return
		sub = kwargs.get('sub')
		new_sub = f'runner.{self.__class__.__name__}'
		if sub:
			new_sub += f'.{sub}'
		kwargs['sub'] = new_sub
		if self.id and not self.sync:
			kwargs['id'] = self.id
		debug(*args, **kwargs)

	def mark_duplicates(self):
		"""Check for duplicates and mark items as duplicates."""
		if not self.enable_duplicate_check:
			return
		self.debug('running duplicate check', sub='end')
		# dupe_count = 0
		import concurrent.futures
		executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)
		for item in self.results.copy():
			executor.submit(self.check_duplicate, item)
		executor.shutdown(wait=True)
		# duplicates = [repr(i) for i in self.results if i._duplicate]
		# if duplicates:
		# 	duplicates_str = '\n\t'.join(duplicates)
		# 	self.debug(f'Duplicates ({dupe_count}):\n\t{duplicates_str}', sub='duplicates', verbose=True)
		# self.debug(f'duplicate check completed: {dupe_count} found', sub='duplicates')

	def check_duplicate(self, item):
		"""Check if an item is a duplicate in the list of results and mark it like so.

		Args:
			item (OutputType): Secator output type.
		"""
		self.debug('running duplicate check for item', obj=item.toDict(), obj_breaklines=True, sub='item.duplicate', verbose=True)  # noqa: E501
		others = [f for f in self.results if f == item and f._uuid != item._uuid]
		if others:
			main = max(item, *others)
			dupes = [f for f in others if f._uuid != main._uuid]
			main._duplicate = False
			main._related.extend([dupe._uuid for dupe in dupes])
			main._related = list(dict.fromkeys(main._related))
			if main._uuid != item._uuid:
				self.debug(f'found {len(others)} duplicates for', obj=item.toDict(), obj_breaklines=True, sub='item.duplicate', verbose=True)  # noqa: E501
				item._duplicate = True
				item = self.run_hooks('on_item', item, sub='item.duplicate')
				if item._uuid not in main._related:
					main._related.append(item._uuid)
				main = self.run_hooks('on_duplicate', main, sub='item.duplicate')
				item = self.run_hooks('on_duplicate', item, sub='item.duplicate')

			for dupe in dupes:
				if not dupe._duplicate:
					self.debug(
						'found new duplicate', obj=dupe.toDict(), obj_breaklines=True,
						sub='item.duplicate', verbose=True)
					dupe._duplicate = True
					dupe = self.run_hooks('on_duplicate', dupe, sub='item.duplicate')

	def yielder(self):
		"""Base yielder implementation.

		This should be overridden by derived classes if they need custom behavior.
		Otherwise, they can implement build_celery_workflow() and get standard behavior.

		Yields:
			secator.output_types.OutputType: Secator output type.
		"""
		# If existing celery result, yield from it
		if self.celery_result:
			yield from CeleryData.iter_results(
				self.celery_result,
				ids_map=self.celery_ids_map,
				description=True,
				revoked=self.revoked,
				print_remote_info=self.print_remote_info,
				print_remote_title=f'[bold gold3]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.name}[/] results'
			)
			return

		# Build Celery workflow
		self.debug('building celery workflow', sub='start')
		workflow = self.build_celery_workflow()
		self.print_target = False

		# Run workflow and get results
		if self.sync:
			self.print_item = False
			self.debug('running workflow in sync mode', sub='start')
			results = workflow.apply().get()
		else:
			self.debug('running workflow in async mode', sub='start')
			self.celery_result = workflow()
			self.celery_ids.append(str(self.celery_result.id))
			yield Info(
				message=f'Celery task created: {self.celery_result.id}',
				task_id=self.celery_result.id
			)
			if self.no_poll:
				self.enable_reports = False
				self.no_process = True
				return
			results = CeleryData.iter_results(
				self.celery_result,
				ids_map=self.celery_ids_map,
				description=True,
				print_remote_info=self.print_remote_info,
				print_remote_title=f'[bold gold3]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.name}[/] results'
			)

		# Yield results
		yield from results

	def build_celery_workflow(self):
		"""Build Celery workflow.

		This should be implemented by derived classes.

		Returns:
			celery.Signature: Celery task signature.
		"""
		raise NotImplementedError("Derived classes must implement build_celery_workflow()")

	def toDict(self):
		"""Dict representation of the runner."""
		data = {
			'name': self.name,
			'status': self.status,
			'targets': self.inputs,
			'start_time': self.start_time,
			'end_time': self.end_time,
			'elapsed': self.elapsed.total_seconds(),
			'elapsed_human': self.elapsed_human,
			'run_opts': self.resolved_opts,
		}
		data.update({
			'config': self.config.toDict(),
			'opts': self.config.supported_opts,
			'has_parent': self.has_parent,
			'has_children': self.has_children,
			'chunk': self.chunk,
			'chunk_count': self.chunk_count,
			'sync': self.sync,
			'done': self.done,
			'output': self.output,
			'progress': self.progress,
			'last_updated_db': self.last_updated_db,
			'context': self.context,
			'errors': [e.toDict() for e in self.errors],
		})
		return data

	def run_hooks(self, hook_type, *args, sub='hooks'):
		""""Run hooks of a certain type.

		Args:
			hook_type (str): Hook type.
			args (list): List of arguments to pass to the hook.
			sub (str): Debug id.

		Returns:
			any: Hook return value.
		"""
		result = args[0] if len(args) > 0 else None
		if self.no_process:
			self.debug('hook skipped (no_process)', obj={'name': hook_type}, sub=sub, verbose=True)  # noqa: E501
			return result
		if self.dry_run:
			self.debug('hook skipped (dry_run)', obj={'name': hook_type}, sub=sub, verbose=True)  # noqa: E501
			return result
		for hook in self.resolved_hooks[hook_type]:
			fun = self.get_func_path(hook)
			try:
				if hook_type == 'on_interval' and not should_update(CONFIG.runners.backend_update_frequency, self.last_updated_db):
					self.debug('hook skipped (backend update frequency)', obj={'name': hook_type, 'fun': fun}, sub=sub, verbose=True)  # noqa: E501
					return
				if not self.enable_hooks or self.no_process:
					self.debug('hook skipped (disabled hooks or no_process)', obj={'name': hook_type, 'fun': fun}, sub=sub, verbose=True)  # noqa: E501
					continue
				result = hook(self, *args)
				self.debug('hook success', obj={'name': hook_type, 'fun': fun}, sub=sub, verbose='item' in sub)  # noqa: E501
				if isinstance(result, Error):
					self.add_result(result, hooks=False)
			except Exception as e:
				self.debug('hook failed', obj={'name': hook_type, 'fun': fun}, sub=sub)  # noqa: E501
				error = Error.from_exception(e, message=f'Hook "{fun}" execution failed')
				if self.raise_on_error:
					raise e
				self.add_result(error, hooks=False)
		return result

	def run_validators(self, validator_type, *args, error=True, sub='validators'):
		"""Run validators of a certain type.

		Args:
			validator_type (str): Validator type. E.g: on_start.
			args (list): List of arguments to pass to the validator.
			error (bool): Whether to add an error to runner results if the validator failed.
			sub (str): Debug id.

		Returns:
			bool: Validator return value.
		"""
		if self.no_process:
			self.debug('validator skipped (no_process)', obj={'name': validator_type}, sub=sub, verbose=True)  # noqa: E501
			return True
		if self.dry_run:
			self.debug('validator skipped (dry_run)', obj={'name': validator_type}, sub=sub, verbose=True)  # noqa: E501
			return True
		for validator in self.resolved_validators[validator_type]:
			fun = self.get_func_path(validator)
			if not validator(self, *args):
				self.debug('validator failed', obj={'name': validator_type, 'fun': fun}, sub=sub)  # noqa: E501
				doc = validator.__doc__
				if error:
					message = 'Validator failed'
					if doc:
						message += f': {doc}'
					err = Error(message=message)
					self.add_result(err)
				return False
			self.debug('validator success', obj={'name': validator_type, 'fun': fun}, sub=sub)  # noqa: E501
		return True

	def register_hooks(self, hooks):
		"""Register hooks.

		Args:
			hooks (dict[str, List[Callable]]): List of hooks to register.
		"""
		for key in self.resolved_hooks:
			# Register class + derived class hooks
			class_hook = getattr(self, key, None)
			if class_hook:
				fun = self.get_func_path(class_hook)
				self.debug('hook registered', obj={'name': key, 'fun': fun}, sub='init')
				self.resolved_hooks[key].append(class_hook)

			# Register user hooks
			user_hooks = hooks.get(self.__class__, {}).get(key, [])
			user_hooks.extend(hooks.get(key, []))
			for hook in user_hooks:
				fun = self.get_func_path(hook)
				self.debug('hook registered', obj={'name': key, 'fun': fun}, sub='init')
			self.resolved_hooks[key].extend(user_hooks)

	def register_validators(self, validators):
		"""Register validators.

		Args:
			validators (dict[str, List[Callable]]): Validators to register.
		"""
		# Register class + derived class hooks
		for key in self.resolved_validators:
			class_validator = getattr(self, key, None)
			if class_validator:
				fun = self.get_func_path(class_validator)
				self.resolved_validators[key].append(class_validator)
				self.debug('validator registered', obj={'name': key, 'fun': fun}, sub='init')

			# Register user hooks
			user_validators = validators.get(key, [])
			for validator in user_validators:
				fun = self.get_func_path(validator)
				self.debug('validator registered', obj={'name': key, 'fun': fun}, sub='init')
			self.resolved_validators[key].extend(user_validators)

	def mark_started(self):
		"""Mark runner as started."""
		if self.started:
			return
		self.started = True
		self.start_time = datetime.fromtimestamp(time())
		self.debug(f'started (sync: {self.sync}, hooks: {self.enable_hooks}), chunk: {self.chunk}, chunk_count: {self.chunk_count}', sub='start')  # noqa: E501
		self.log_start()
		self.run_hooks('on_start', sub='start')

	def mark_completed(self):
		"""Mark runner as completed."""
		if self.done:
			return
		self.started = True
		self.done = True
		self.progress = 100
		self.end_time = datetime.fromtimestamp(time())
		self.debug(f'completed (status: {self.status}, sync: {self.sync}, reports: {self.enable_reports}, hooks: {self.enable_hooks})', sub='end')  # noqa: E501
		self.mark_duplicates()
		self.run_hooks('on_end', sub='end')
		self.export_profiler()
		self.log_results()

	def log_start(self):
		"""Log runner start."""
		if not self.print_start:
			return
		if self.has_parent:
			return
		if self.config.type != 'task':
			tree = textwrap.indent(build_runner_tree(self.config).render_tree(), '      ')
			info = Info(message=f'{self.config.type.capitalize()} built:\n{tree}', _source=self.unique_name)
			self._print(info, rich=True)
		remote_str = 'started' if self.sync else 'started in worker'
		msg = f'{self.config.type.capitalize()} {format_runner_name(self)}'
		if self.description:
			msg += f' ([dim]{self.description}[/])'
		info = Info(message=f'{msg} {remote_str}', _source=self.unique_name)
		self._print(info, rich=True)

	def log_results(self):
		"""Log runner results."""
		if not self.print_end:
			return
		if self.has_parent:
			return
		info = Info(
			message=(
				f'{self.config.type.capitalize()} {format_runner_name(self)} finished with status '
				f'[bold {STATE_COLORS[self.status]}]{self.status}[/] and found '
				f'[bold]{len(self.findings)}[/] findings'
			)
		)
		self._print(info, rich=True)

	def export_reports(self):
		"""Export reports."""
		if self.enable_reports and self.exporters and not self.no_process and not self.dry_run:
			if self.print_end:
				exporters_str = ', '.join([f'[bold cyan]{e.__name__.replace("Exporter", "").lower()}[/]' for e in self.exporters])
				self._print(Info(message=f'Exporting results with exporters: {exporters_str}'), rich=True)
			report = Report(self, exporters=self.exporters)
			report.build()
			report.send()
			self.report = report

	def export_profiler(self):
		"""Export profiler."""
		if self.enable_pyinstrument:
			self.debug('stopping profiler', sub='end')
			self.profiler.stop()
			profile_path = Path(self.reports_folder) / f'{self.unique_name}_profile.html'
			with profile_path.open('w', encoding='utf-8') as f_html:
				f_html.write(self.profiler.output_html())
			self._print_item(Info(message=f'Wrote profile to {str(profile_path)}'), force=True)

	def stop_celery_tasks(self):
		"""Stop all tasks running in Celery worker."""
		from secator.celery import revoke_task
		for task_id in self.celery_ids:
			name = self.celery_ids_map.get(task_id, {}).get('full_name')
			revoke_task(task_id, name)

	def _convert_item_schema(self, item):
		"""Convert dict item to a secator output type.

		Args:
			item (dict): Dict item.

		Returns:
			OutputType: Loaded item.
		"""
		# Skip if already converted
		if isinstance(item, OutputType):
			return item

		# Init the new item and the list of output types to load from
		new_item = None
		output_types = getattr(self, 'output_types', [])
		self.debug(f'input item: {item}', sub='item.convert', verbose=True)

		# Use a function to pick proper output types
		output_discriminator = getattr(self, 'output_discriminator', None)
		if output_discriminator:
			result = output_discriminator(item)
			if result:
				self.debug('discriminated output type with output_discriminator', sub='item.convert', verbose=True)
				output_types = [result]
			else:
				output_types = []

		# Use the _type key to pick proper output type
		elif '_type' in item:
			otypes = [o for o in output_types if o.get_name() == item['_type']]
			if otypes:
				output_types = [otypes[0]]
				self.debug('discriminated output type with _type key', sub='item.convert', verbose=True)

		# Load item using picked output types
		self.debug(f'output types to try: {[str(o) for o in output_types]}', sub='item.convert', verbose=True)
		for klass in output_types:
			self.debug(f'loading item as {str(klass)}', sub='item.convert', verbose=True)
			output_map = getattr(self, 'output_map', {}).get(klass, {})
			try:
				new_item = klass.load(item, output_map)
				self.debug(f'successfully loaded item as {str(klass)}', sub='item.convert', verbose=True)
				break
			except (TypeError, KeyError) as e:
				self.debug(
					f'failed loading item as {str(klass)}: {type(e).__name__}: {str(e)}.',
					sub='item.convert', verbose=True)
				# error = Error.from_exception(e)
				# self.debug(repr(error), sub='debug.klass.load')
				continue

		if not new_item:
			new_item = Warning(message=f'Failed to load item as output type:\n  {item}')

		self.debug(f'output item: {new_item.toDict()}', sub='item.convert', verbose=True)

		return new_item

	def _print(self, data, color=None, out=sys.stderr, rich=False, end='\n'):
		"""Print function.

		Args:
			data (str or dict): Input data.
			color (str, Optional): Rich color.
			out (str, Optional): Output pipe (sys.stderr, sys.stdout, ...)
			rich (bool, Optional): Force rich output.
			end (str, Optional): End of line.
			add_to_output (bool, Optional): Whether to add the item to runner output.
		"""
		if rich:
			_console = console_stdout if out == sys.stdout else console
			_console.print(data, highlight=False, style=color, soft_wrap=True, end=end)
		else:
			if isinstance(data, (OutputType, dict)):
				if getattr(data, 'toDict', None):
					data = data.toDict()
				data = json.dumps(data, default=str)
			print(data, file=out)

	def _get_findings_count(self):
		"""Get finding count.

		Returns:
			dict[str,int]: Dict of finding type to count.
		"""
		count_map = {}
		for output_type in FINDING_TYPES:
			name = output_type.get_name()
			count = len([r for r in self.results if isinstance(r, output_type)])
			if count > 0:
				count_map[name] = count
		return count_map

	def _process_item(self, item, print=True, output=True):
		"""Process an item yielded by the derived runner.

		Args:
			item (dict | str): Input item.
			print (bool): Print item in console.
			output (bool): Add to runner output.

		Yields:
			OutputType: Output type.
		"""
		# Item is a string, just print it
		if isinstance(item, str):
			self.output += item + '\n' if output else ''
			self._print_item(item) if item and print else ''
			return

		# Abort further processing if no_process is set
		if self.no_process:
			return

		# Run item validators
		if not self.run_validators('validate_item', item, error=False, sub='item'):
			return

		# Convert output dict to another schema
		if isinstance(item, dict):
			item = self.run_hooks('on_item_pre_convert', item, sub='item')
			if not item:
				return
			item = self._convert_item_schema(item)

		# Add item to results
		self.add_result(item, print=print, queue=False)

		# Yield item
		yield item

	@staticmethod
	def _validate_inputs(self, inputs):
		"""Input type is not supported by runner"""
		supported_types = ', '.join(self.config.input_types) if self.config.input_types else 'any'
		for _input in inputs:
			input_type = autodetect_type(_input)
			if self.config.input_types and input_type not in self.config.input_types:
				message = (
					f'Validator failed: target [bold blue]{_input}[/] of type [bold green]{input_type}[/] '
					f'is not supported by [bold gold3]{self.unique_name}[/]. Supported types: [bold green]{supported_types}[/]'
				)
				if self.has_parent:
					message += '. Removing from current inputs (runner context)'
					info = Info(message=message)
					self.inputs.remove(_input)
					self.add_result(info)
				else:
					error = Error(message=message)
					self.add_result(error)
					return False
		return True

	@staticmethod
	def resolve_exporters(exporters):
		"""Resolve exporters from output options.

		Args:
			exporters (list[str]): List of exporters to resolve.

		Returns:
			list: List of exporter classes.
		"""
		if not exporters or exporters in ['false', 'False']:
			return []
		if isinstance(exporters, str):
			exporters = exporters.split(',')
		classes = [
			import_dynamic('secator.exporters', f'{o.capitalize()}Exporter')
			for o in exporters
			if o
		]
		return [cls for cls in classes if cls]

	def resolve_profiles(self, profiles):
		"""Resolve profiles and update run options.

		Args:
			profiles (list[str]): List of profile names to resolve.

		Returns:
			list: List of profiles.
		"""
		# Return if profiles are disabled
		if not self.enable_profiles:
			return []

		# Split profiles if comma separated
		if isinstance(profiles, str):
			profiles = profiles.split(',')

		# Add default profiles
		default_profiles = CONFIG.profiles.defaults
		for p in default_profiles:
			if p in profiles:
				continue
			profiles.append(p)

		# Abort if no profiles
		if not profiles:
			return []

		# Get profile configs
		templates = []
		profile_configs = get_configs_by_type('profile')
		for pname in profiles:
			matches = [p for p in profile_configs if p.name == pname]
			if not matches:
				self._print(Warning(message=f'Profile "{pname}" was not found. Run [bold green]secator profiles list[/] to see available profiles.'), rich=True)  # noqa: E501
			else:
				templates.append(matches[0])

		if not templates:
			self.debug('no profiles loaded', sub='init')
			return

		# Put enforced profiles last
		enforced_templates = [p for p in templates if p.enforce]
		non_enforced_templates = [p for p in templates if not p.enforce]
		templates = non_enforced_templates + enforced_templates
		profile_opts = {}
		for profile in templates:
			self.debug(f'profile {profile.name} opts (enforced: {profile.enforce}): {profile.opts}', sub='init')
			enforced = profile.enforce or False
			description = profile.description or ''
			if enforced:
				profile_opts.update(profile.opts)
			else:
				profile_opts.update({k: self.run_opts.get(k) or v for k, v in profile.opts.items()})
			if self.print_profiles:
				msg = f'Loaded profile [bold pink3]{profile.name}[/]'
				if description:
					msg += f' ([dim]{description}[/])'
				if enforced:
					msg += ' [bold red](enforced)[/]'
				profile_opts_str = ", ".join([f'[bold yellow3]{k}[/]=[dim yellow3]{v}[/]' for k, v in profile.opts.items()])
				msg += rf' \[[dim]{profile_opts_str}[/]]'
				self._print(Info(message=msg), rich=True)
		if profile_opts:
			self.run_opts.update(profile_opts)
		return templates

	@classmethod
	def get_func_path(cls, func):
		"""Get the full symbolic path of a function or method, including staticmethods, using function and method
		attributes.

		Args:
			func (function, method, or staticmethod): A function or method object.
		"""
		if hasattr(func, '__self__'):
			if func.__self__ is not None:
				# It's a method bound to an instance
				class_name = func.__self__.__class__.__name__
				return f"{func.__module__}.{class_name}.{func.__name__}"
			else:
				# It's a method bound to a class (class method)
				class_name = func.__qualname__.rsplit('.', 1)[0]
				return f"{func.__module__}.{class_name}.{func.__name__}"
		else:
			# Handle static and regular functions
			if '.' in func.__qualname__:
				# Static method or a function defined inside a class
				class_name, func_name = func.__qualname__.rsplit('.', 1)
				return f"{func.__module__}.{class_name}.{func_name}"
			else:
				# Regular function not attached to a class
				return f"{func.__module__}.{func.__name__}"
