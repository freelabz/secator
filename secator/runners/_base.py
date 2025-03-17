import json
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from time import time

import humanize

from secator.definitions import ADDONS_ENABLED
from secator.celery_utils import CeleryData
from secator.config import CONFIG
from secator.output_types import FINDING_TYPES, OutputType, Progress, Info, Warning, Error, Target, State
from secator.report import Report
from secator.rich import console, console_stdout
from secator.runners._helpers import (get_task_folder_id, run_extractors)
from secator.utils import (debug, import_dynamic, rich_to_ansi, should_update)

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
	input_type = None

	# Output types
	output_types = []

	# Default exporters
	default_exporters = []

	# Run hooks
	enable_hooks = True

	# Reports folder
	reports_folder = None

	def __init__(self, config, inputs=[], results=[], run_opts={}, hooks={}, validators={}, context={}):
		self.uuids = []
		self.results = []
		self.output = ''

		# Runner config
		self.config = config
		self.name = run_opts.get('name', config.name)
		self.description = run_opts.get('description', config.description)
		self.workspace_name = context.get('workspace_name', 'default')
		self.run_opts = run_opts.copy()
		self.sync = run_opts.get('sync', True)
		self.done = False
		self.start_time = datetime.fromtimestamp(time())
		self.last_updated_db = None
		self.last_updated_celery = None
		self.last_updated_progress = None
		self.end_time = None
		self._hooks = hooks
		self.progress = 0
		self.context = context
		self.delay = run_opts.get('delay', False)
		self.celery_result = None
		self.celery_ids = []
		self.celery_ids_map = {}
		self.caller = self.run_opts.get('caller', None)
		self.threads = []
		self.no_poll = self.run_opts.get('no_poll', False)
		self.quiet = self.run_opts.get('quiet', False)
		self.started = False

		# Runner process options
		self.no_process = self.run_opts.get('no_process', False)
		self.piped_input = self.run_opts.get('piped_input', False)
		self.piped_output = self.run_opts.get('piped_output', False)
		self.enable_duplicate_check = self.run_opts.get('enable_duplicate_check', True)

		# Runner print opts
		self.print_item = self.run_opts.get('print_item', False)
		self.print_line = self.run_opts.get('print_line', False) and not self.quiet
		self.print_remote_info = self.run_opts.get('print_remote_info', False) and not self.piped_input and not self.piped_output  # noqa: E501
		self.print_json = self.run_opts.get('print_json', False)
		self.print_raw = self.run_opts.get('print_raw', False) or self.piped_output
		self.print_fmt = self.run_opts.get('fmt', '')
		self.print_progress = self.run_opts.get('print_progress', False) and not self.quiet and not self.print_raw
		self.print_target = self.run_opts.get('print_target', False) and not self.quiet and not self.print_raw
		self.print_stat = self.run_opts.get('print_stat', False) and not self.quiet and not self.print_raw
		self.raise_on_error = self.run_opts.get('raise_on_error', False)
		self.print_opts = {k: v for k, v in self.__dict__.items() if k.startswith('print_') if v}

		# Chunks
		self.has_parent = self.run_opts.get('has_parent', False)
		self.has_children = self.run_opts.get('has_children', False)
		self.chunk = self.run_opts.get('chunk', None)
		self.chunk_count = self.run_opts.get('chunk_count', None)
		self.unique_name = self.name.replace('/', '_')
		self.unique_name = f'{self.unique_name}_{self.chunk}' if self.chunk else self.unique_name

		# Add prior results to runner results
		[self.add_result(result, print=False, output=False) for result in results]

		# Determine inputs
		inputs = [inputs] if not isinstance(inputs, list) else inputs
		if not self.chunk and self.results:
			inputs, run_opts, errors = run_extractors(self.results, run_opts, inputs)
			for error in errors:
				self.add_result(error, print=True)
		self.inputs = inputs

		# Debug
		self.debug('Inputs', obj=self.inputs, sub='init')
		self.debug('Run opts', obj={k: v for k, v in self.run_opts.items() if v is not None}, sub='init')
		self.debug('Print opts', obj={k: v for k, v in self.print_opts.items() if v is not None}, sub='init')

		# Determine exporters
		exporters_str = self.run_opts.get('output') or self.default_exporters
		self.exporters = self.resolve_exporters(exporters_str)

		# Determine report folder
		default_reports_folder_base = f'{CONFIG.dirs.reports}/{self.workspace_name}/{self.config.type}s'
		_id = get_task_folder_id(default_reports_folder_base)
		self.reports_folder = f'{default_reports_folder_base}/{_id}'

		# Make reports folders
		os.makedirs(self.reports_folder, exist_ok=True)
		os.makedirs(f'{self.reports_folder}/.inputs', exist_ok=True)
		os.makedirs(f'{self.reports_folder}/.outputs', exist_ok=True)

		# Profiler
		self.enable_profiler = self.run_opts.get('enable_profiler', False) and ADDONS_ENABLED['trace']
		if self.enable_profiler:
			from pyinstrument import Profiler
			self.profiler = Profiler(async_mode=False, interval=0.0001)
			try:
				self.profiler.start()
			except RuntimeError:
				self.enable_profiler = False
				pass

		# Hooks
		self.hooks = {name: [] for name in HOOKS + getattr(self, 'hooks', [])}
		self.register_hooks(hooks)

		# Validators
		self.validators = {name: [] for name in VALIDATORS + getattr(self, 'validators', [])}
		self.register_validators(validators)

		# Input post-process
		self.run_hooks('before_init')

		# Check if input is valid
		self.inputs_valid = self.run_validators('validate_input', self.inputs)

		# Run hooks
		self.run_hooks('on_init')

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
			'descr': self.config.description or '',
		}

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
			self.log_start()
			self.run_hooks('on_start')

			# If any errors happened during valid ation, exit
			if self.errors:
				yield from self.errors
				if self.no_process:
					return
				self.log_results()
				self.run_hooks('on_end')
				return

			# Loop and process items
			for item in self.yielder():
				yield from self._process_item(item)
				self.run_hooks('on_interval')

			# Wait for threads to finish
			yield from self.join_threads()

		except BaseException as e:
			self.debug(f'encountered exception {type(e).__name__}. Stopping remote tasks.', sub='error')
			error = Error.from_exception(e)
			error._source = self.unique_name
			error._uuid = str(uuid.uuid4())
			self.add_result(error, print=True)
			self.stop_celery_tasks()
			yield from self.join_threads()
			yield error

		finally:
			if self.no_process:
				return
			self.mark_duplicates()
			self.log_results()
			self.run_hooks('on_end')

	def join_threads(self):
		"""Wait for all running threads to complete."""
		if not self.threads:
			return
		self.debug(f'waiting for {len(self.threads)} threads to complete')
		for thread in self.threads:
			error = thread.join()
			if error:
				error._source = self.unique_name
				error._uuid = str(uuid.uuid4())
				self.add_result(error, print=True)
				yield error

	def add_result(self, item, print=False, output=True):
		"""Add item to runner results.

		Args:
			item (OutputType): Item.
			print (bool): Whether to print it or not.
			output (bool): Whether to add it to the output or not.
		"""
		self.uuids.append(item._uuid)
		self.results.append(item)
		if output:
			self.output += repr(item) + '\n'
		if print:
			self._print_item(item)

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
			self.debug(item, lazy=lambda x: repr(x), sub='item', allow_no_process=False, verbose=True)
			_type = item._type
			print_this_type = getattr(self, f'print_{_type}', True)
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
					if isinstance(item, OutputType) and self.print_remote_info:
						item_repr += rich_to_ansi(rf' \[[dim]{item._source}[/]]')
					self._print(item_repr, out=item_out)

		# Item is a line
		elif isinstance(item, str):
			self.debug(item, sub='line', allow_no_process=False, verbose=True)
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
		debug(*args, **kwargs)

	def mark_duplicates(self):
		"""Check for duplicates and mark items as duplicates."""
		if not self.enable_duplicate_check:
			return
		self.debug('running duplicate check', id=self.config.name, sub='duplicates')
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
		# self.debug(f'duplicate check completed: {dupe_count} found', id=self.config.name, sub='duplicates')

	def check_duplicate(self, item):
		"""Check if an item is a duplicate in the list of results and mark it like so.

		Args:
			item (OutputType): Secator output type.
		"""
		self.debug('running duplicate check for item', obj=item.toDict(), obj_breaklines=True, sub='duplicates', verbose=True)
		others = [f for f in self.results if f == item and f._uuid != item._uuid]
		if others:
			main = max(item, *others)
			dupes = [f for f in others if f._uuid != main._uuid]
			main._duplicate = False
			main._related.extend([dupe._uuid for dupe in dupes])
			main._related = list(dict.fromkeys(main._related))
			if main._uuid != item._uuid:
				self.debug(f'found {len(others)} duplicates for', obj=item.toDict(), obj_breaklines=True, sub='duplicates', verbose=True)  # noqa: E501
				item._duplicate = True
				item = self.run_hooks('on_item', item)
				if item._uuid not in main._related:
					main._related.append(item._uuid)
				main = self.run_hooks('on_duplicate', main)
				item = self.run_hooks('on_duplicate', item)

			for dupe in dupes:
				if not dupe._duplicate:
					self.debug(
						'found new duplicate', obj=dupe.toDict(), obj_breaklines=True,
						sub='duplicates', verbose=True)
					# dupe_count += 1
					dupe._duplicate = True
					dupe = self.run_hooks('on_duplicate', dupe)

	def yielder(self):
		"""Base yielder implementation.

		This should be overridden by derived classes if they need custom behavior.
		Otherwise, they can implement build_celery_workflow() and get standard behavior.

		Yields:
			secator.output_types.OutputType: Secator output type.
		"""
		# Build Celery workflow
		workflow = self.build_celery_workflow()

		# Run workflow and get results
		if self.sync:
			self.print_item = False
			self.started = True
			results = workflow.apply().get()
			yield from results
		else:
			self.celery_result = workflow()
			self.celery_ids.append(str(self.celery_result.id))
			yield Info(
				message=f'Celery task created: {self.celery_result.id}',
				task_id=self.celery_result.id
			)
			if self.no_poll:
				self.enable_hooks = False
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
			'run_opts': {k: v for k, v in self.run_opts.items() if k not in self.print_opts},
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

	def run_hooks(self, hook_type, *args):
		""""Run hooks of a certain type.

		Args:
			hook_type (str): Hook type.
			args (list): List of arguments to pass to the hook.

		Returns:
			any: Hook return value.
		"""
		result = args[0] if len(args) > 0 else None
		_id = self.context.get('task_id', '') or self.context.get('workflow_id', '') or self.context.get('scan_id', '')
		for hook in self.hooks[hook_type]:
			name = f'{self.__class__.__name__}.{hook_type}'
			fun = self.get_func_path(hook)
			try:
				if hook_type == 'on_interval' and not should_update(CONFIG.runners.backend_update_frequency, self.last_updated_db):
					self.debug('', obj={f'{name} [dim yellow]->[/] {fun}': '[dim gray11]skipped[/]'}, id=_id, sub='hooks', verbose=True)  # noqa: E501
					return
				if not self.enable_hooks or self.no_process:
					self.debug('', obj={f'{name} [dim yellow]->[/] {fun}': '[dim gray11]skipped[/]'}, id=_id, sub='hooks', verbose=True)  # noqa: E501
					continue
				# self.debug('', obj={f'{name} [dim yellow]->[/] {fun}': '[dim yellow]started[/]'}, id=_id, sub='hooks', verbose=True)  # noqa: E501
				result = hook(self, *args)
				self.debug('', obj={f'{name} [dim yellow]->[/] {fun}': '[dim green]success[/]'}, id=_id, sub='hooks', verbose=True)  # noqa: E501
			except Exception as e:
				self.debug('', obj={f'{name} [dim yellow]->[/] {fun}': '[dim red]failed[/]'}, id=_id, sub='hooks', verbose=True)  # noqa: E501
				error = Error.from_exception(e)
				error.message = f'Hook "{fun}" execution failed.'
				error._source = self.unique_name
				error._uuid = str(uuid.uuid4())
				self.add_result(error, print=True)
				if self.raise_on_error:
					raise e
		return result

	def run_validators(self, validator_type, *args, error=True):
		"""Run validators of a certain type.

		Args:
			validator_type (str): Validator type. E.g: on_start.
			args (list): List of arguments to pass to the validator.
			error (bool): Whether to add an error to runner results if the validator failed.

		Returns:
			bool: Validator return value.
		"""
		if self.no_process:
			return True
		_id = self.context.get('task_id', '') or self.context.get('workflow_id', '') or self.context.get('scan_id', '')
		for validator in self.validators[validator_type]:
			name = f'{self.__class__.__name__}.{validator_type}'
			fun = self.get_func_path(validator)
			if not validator(self, *args):
				self.debug('', obj={name + ' [dim yellow]->[/] ' + fun: '[dim red]failed[/]'}, id=_id, verbose=True, sub='validators')  # noqa: E501
				doc = validator.__doc__
				if error:
					message = 'Validator failed'
					if doc:
						message += f': {doc}'
					error = Error(
						message=message,
						_source=self.unique_name,
						_uuid=str(uuid.uuid4())
					)
					self.add_result(error, print=True)
				return False
			self.debug('', obj={name + ' [dim yellow]->[/] ' + fun: '[dim green]success[/]'}, id=_id, verbose=True, sub='validators')  # noqa: E501
		return True

	def register_hooks(self, hooks):
		"""Register hooks.

		Args:
			hooks (dict[str, List[Callable]]): List of hooks to register.
		"""
		for key in self.hooks:
			# Register class + derived class hooks
			class_hook = getattr(self, key, None)
			if class_hook:
				name = f'{self.__class__.__name__}.{key}'
				fun = self.get_func_path(class_hook)
				self.debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'registered'}, sub='hooks')
				self.hooks[key].append(class_hook)

			# Register user hooks
			user_hooks = hooks.get(self.__class__, {}).get(key, [])
			user_hooks.extend(hooks.get(key, []))
			for hook in user_hooks:
				name = f'{self.__class__.__name__}.{key}'
				fun = self.get_func_path(hook)
				self.debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'registered (user)'}, sub='hooks')
			self.hooks[key].extend(user_hooks)

	def register_validators(self, validators):
		"""Register validators.

		Args:
			validators (dict[str, List[Callable]]): Validators to register.
		"""
		# Register class + derived class hooks
		for key in self.validators:
			class_validator = getattr(self, key, None)
			if class_validator:
				name = f'{self.__class__.__name__}.{key}'
				fun = self.get_func_path(class_validator)
				self.validators[key].append(class_validator)
				self.debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'registered'}, sub='validators')

			# Register user hooks
			user_validators = validators.get(key, [])
			for validator in user_validators:
				name = f'{self.__class__.__name__}.{key}'
				fun = self.get_func_path(validator)
				self.debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'registered (user)'}, sub='validators')
			self.validators[key].extend(user_validators)

	def log_start(self):
		"""Log runner start."""
		if not self.print_remote_info:
			return
		remote_str = 'starting' if self.sync else 'sent to Celery worker'
		runner_name = self.__class__.__name__
		info = Info(message=f'{runner_name} {self.config.name} {remote_str}...', _source=self.unique_name)
		self._print_item(info)

	def log_results(self):
		"""Log runner results."""
		self.started = True
		self.done = True
		self.progress = 100
		self.end_time = datetime.fromtimestamp(time())
		if self.status == 'FAILURE':
			self.debug('', obj={self.__class__.__name__: self.status, 'errors': [str(_.message) for _ in self.errors]}, sub='status')  # noqa: E501
		else:
			self.debug('', obj={self.__class__.__name__: self.status}, sub='status')
		if self.exporters and not self.no_process:
			report = Report(self, exporters=self.exporters)
			report.build()
			report.send()
			self.report = report
		if self.enable_profiler:
			self.profiler.stop()
			profile_path = Path(self.reports_folder) / f'{self.unique_name}_profile.html'
			with profile_path.open('w', encoding='utf-8') as f_html:
				f_html.write(self.profiler.output_html())
			self._print_item(Info(message=f'Wrote profile to {str(profile_path)}', _source=self.unique_name), force=True)

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
		self.debug(f'Input item: {item}', sub='klass.load', verbose=True)

		# Use a function to pick proper output types
		output_discriminator = getattr(self, 'output_discriminator', None)
		if output_discriminator:
			result = output_discriminator(item)
			if result:
				self.debug(f'Discriminated output type: {result.__name__}', sub='klass.load', verbose=True)
				output_types = [result]
			else:
				output_types = []

		# Use the _type key to pick proper output type
		elif '_type' in item:
			otypes = [o for o in output_types if o.get_name() == item['_type']]
			if otypes:
				output_types = [otypes[0]]
				self.debug(f'_type key is present in item and matches {otypes[0]}', sub='klass.load', verbose=True)

		# Load item using picked output types
		self.debug(f'Output types to try: {[o.__name__ for o in output_types]}', sub='klass.load', verbose=True)
		for klass in output_types:
			self.debug(f'Loading item as {klass.__name__}', sub='klass.load', verbose=True)
			output_map = getattr(self, 'output_map', {}).get(klass, {})
			try:
				new_item = klass.load(item, output_map)
				self.debug(f'[dim green]Successfully loaded item as {klass.__name__}[/]', sub='klass.load', verbose=True)
				break
			except (TypeError, KeyError) as e:
				self.debug(
					f'[dim red]Failed loading item as {klass.__name__}: {type(e).__name__}: {str(e)}.[/] [dim green]Continuing.[/]',
					sub='klass.load', verbose=True)
				# error = Error.from_exception(e)
				# self.debug(repr(error), sub='debug.klass.load')
				continue

		if not new_item:
			new_item = Warning(message=f'Failed to load item as output type:\n  {item}')

		self.debug(f'Output item: {new_item.toDict()}', sub='klass.load', verbose=True)

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
				data = json.dumps(data)
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
		if not self.run_validators('validate_item', item, error=False):
			return

		# Convert output dict to another schema
		if isinstance(item, dict):
			item = self.run_hooks('on_item_pre_convert', item)
			if not item:
				return
			item = self._convert_item_schema(item)

		# Update item context
		item._context.update(self.context)

		# Add uuid to item
		if not item._uuid:
			item._uuid = str(uuid.uuid4())

		# Return if already seen
		if item._uuid in self.uuids:
			return

		# Add source to item
		if not item._source:
			item._source = self.unique_name

		# Check for state updates
		if isinstance(item, State) and self.celery_result and item.task_id == self.celery_result.id:
			self.debug(f'Updating runner state from Celery: {item.state}', sub='state')
			if item.state in ['FAILURE', 'SUCCESS', 'REVOKED']:
				self.started = True
				self.done = True
			elif item.state in ['RUNNING']:
				self.started = True
			self.debug(f'Runner {self.unique_name} is {self.status} (started: {self.started}, done: {self.done})', sub='state')
			self.last_updated_celery = item._timestamp
			return

		# If progress item, update runner progress
		elif isinstance(item, Progress) and item._source == self.unique_name:
			self.progress = item.percent
			if not should_update(CONFIG.runners.progress_update_frequency, self.last_updated_progress, item._timestamp):
				return
			elif int(item.percent) in [0, 100]:
				return
			else:
				self.last_updated_progress = item._timestamp

		# If info item and task_id is defined, update runner celery_ids
		elif isinstance(item, Info) and item.task_id and item.task_id not in self.celery_ids:
			self.celery_ids.append(item.task_id)

		# If finding, run on_item hooks
		elif isinstance(item, tuple(FINDING_TYPES)):
			item = self.run_hooks('on_item', item)
			if not item:
				return

		# Add item to results
		self.add_result(item, print=print)

		# Yield item
		yield item

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
