import json
import logging
import os
import sys
import traceback
import uuid
from datetime import datetime
from time import time

import humanize
from dotmap import DotMap
from rich.panel import Panel

from secator.definitions import DEBUG
from secator.config import CONFIG
from secator.celery_utils import CeleryData
from secator.output_types import OUTPUT_TYPES, OutputType, Error
from secator.report import Report
from secator.rich import console, console_stdout
from secator.runners._helpers import (get_task_folder_id, process_extractor)
from secator.utils import (debug, import_dynamic, merge_opts, pluralize, rich_to_ansi)

logger = logging.getLogger(__name__)

HOOKS = [
	'before_init',
	'on_init',
	'on_end',
	'on_item_pre_convert',
	'on_item',
	'on_duplicate',
	'on_iter',
]

VALIDATORS = [
	'input',
	'item'
]


class Runner:
	"""Runner class.

	Args:
		config (secator.config.TemplateLoader): Loaded config.
		targets (list): List of targets to run task on.
		results (list): List of existing results to re-use.
		workspace_name (str): Workspace name.
		run_opts (dict): Run options.

	Yields:
		dict: Result (when running in sync mode with `run`).

	Returns:
		list: List of results (when running in async mode with `run_async`).
	"""

	# Input field (mostly for tests and CLI)
	input_type = None

	# Output types
	output_types = []

	# Dict return
	output_return_type = dict  # TODO: deprecate this

	# Default exporters
	default_exporters = []

	# Run hooks
	enable_hooks = True

	# Reports folder
	reports_folder = None

	def __init__(self, config, targets, results=[], run_opts={}, hooks={}, context={}):
		self.config = config
		self.name = run_opts.get('name', config.name)
		self.description = run_opts.get('description', config.description)
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.results = results
		self.results_count = 0
		self.workspace_name = context.get('workspace_name', 'default')
		self.run_opts = run_opts.copy()
		self.sync = run_opts.get('sync', True)
		self.done = False
		self.start_time = datetime.fromtimestamp(time())
		self.last_updated = None
		self.last_updated_progress = None
		self.end_time = None
		self._hooks = hooks
		self.errors = []
		self.infos = []
		self.output = ''
		self.status = 'RUNNING'
		self.progress = 0
		self.context = context
		self.delay = run_opts.get('delay', False)
		self.uuids = []
		self.celery_result = None
		self.celery_ids = []

		# Determine exporters
		exporters_str = self.run_opts.get('output') or self.default_exporters
		self.exporters = Runner.resolve_exporters(exporters_str)

		# Determine report folder
		default_reports_folder_base = f'{CONFIG.dirs.reports}/{self.workspace_name}/{self.config.type}s'
		_id = get_task_folder_id(default_reports_folder_base)
		self.reports_folder = f'{default_reports_folder_base}/{_id}'

		# Make reports folders
		os.makedirs(self.reports_folder, exist_ok=True)
		os.makedirs(f'{self.reports_folder}/.inputs', exist_ok=True)
		os.makedirs(f'{self.reports_folder}/.outputs', exist_ok=True)

		# Process input
		self.input = targets
		if isinstance(self.input, list) and len(self.input) == 1:
			self.input = self.input[0]

		# Yield dicts if CLI supports JSON
		if self.output_return_type is dict or (self.json_flag is not None):
			self.output_return_type = dict

		# Output options
		self.output_fmt = self.run_opts.get('format', False)
		self.output_quiet = self.run_opts.get('quiet', False)
		self.output_json = self.output_return_type == dict

		# Print options
		self.print_start = self.run_opts.pop('print_start', False)
		self.print_item = self.run_opts.pop('print_item', False)
		self.print_line = self.run_opts.pop('print_line', False)
		self.print_errors = self.run_opts.pop('print_errors', True)
		self.print_item_count = self.run_opts.pop('print_item_count', False)
		self.print_cmd = self.run_opts.pop('print_cmd', False)
		self.print_run_opts = self.run_opts.pop('print_run_opts', DEBUG > 1)
		self.print_fmt_opts = self.run_opts.pop('print_fmt_opts', DEBUG > 1)
		self.print_input_file = self.run_opts.pop('print_input_file', False)
		self.print_hooks = self.run_opts.pop('print_hooks', DEBUG > 1)
		self.print_cmd_prefix = self.run_opts.pop('print_cmd_prefix', False)
		self.print_remote_status = self.run_opts.pop('print_remote_status', False)
		self.print_run_summary = self.run_opts.pop('print_run_summary', False)
		self.print_json = self.run_opts.get('json', False)
		self.print_raw = self.run_opts.get('raw', False)
		self.orig = self.run_opts.get('orig', False)
		self.opts_to_print = {k: v for k, v in self.__dict__.items() if k.startswith('print_') if v}

		# Hooks
		self.raise_on_error = self.run_opts.get('raise_on_error', False)
		self.hooks = {name: [] for name in HOOKS + getattr(self, 'hooks', [])}
		for key in self.hooks:

			# Register class + derived class hooks
			class_hook = getattr(self, key, None)
			if class_hook:
				name = f'{self.__class__.__name__}.{key}'
				fun = self.get_func_path(class_hook)
				debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'registered'}, sub='hooks', level=3)
				self.hooks[key].append(class_hook)

			# Register user hooks
			user_hooks = hooks.get(self.__class__, {}).get(key, [])
			user_hooks.extend(hooks.get(key, []))
			for hook in user_hooks:
				name = f'{self.__class__.__name__}.{key}'
				fun = self.get_func_path(hook)
				debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'registered (user)'}, sub='hooks', level=3)
			self.hooks[key].extend(user_hooks)

		# Validators
		self.validators = {name: [] for name in VALIDATORS}
		for key in self.validators:
			instance_func = getattr(self, f'validate_{key}', None)
			if instance_func:
				self.validators[key].append(instance_func)
			self.validators[key].extend(self.validators.get(self.__class__, {}).get(key, []))

		# Chunks
		self.parent = self.run_opts.get('parent', True)
		self.has_children = self.run_opts.get('has_children', False)
		self.chunk = self.run_opts.get('chunk', None)
		self.chunk_count = self.run_opts.get('chunk_count', None)
		self.unique_name = self.name.replace('/', '_')
		self.unique_name = f'{self.unique_name}_{self.chunk}' if self.chunk else self.unique_name
		self._set_print_prefix()

		# Input post-process
		self.run_hooks('before_init')

		# Abort if inputs are invalid
		self.input_valid = True
		if not self.run_validators('input', self.input):
			self.input_valid = False

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

	def run(self):
		return list(self.__iter__())

	def __iter__(self):
		if self.print_start:
			self.log_start()

		if not self.input_valid:
			return

		try:
			for item in self.yielder():
				if isinstance(item, (OutputType, DotMap, dict)):
					item = self._process_item(item)
					if not item or item._uuid in self.uuids:
						continue
					elif isinstance(item, DotMap) and not self.orig:
						orig_item = {
							k: v for k, v in item.toDict().items() if k not in ['_type', '_context', '_source', '_uuid']
						}
						item = Error(
							message=f'Failed to load item as output type:\n  {orig_item}',
							_source=self.config.name,
							_uuid=str(uuid.uuid4())
						)
					if item._type == 'info' and item.task_id:
						self.celery_ids.append(item.task_id)
					self.results.append(item)
					self.results_count += 1
					self.uuids.append(item._uuid)
					yield item

				self._print_item(item)
				self.run_hooks('on_iter')

		except KeyboardInterrupt:
			self._print('Process was killed manually (CTRL+C / CTRL+X).', color='bold red', rich=True)
			if self.celery_result:
				self._print('Revoking remote Celery tasks ...', color='bold red', rich=True)
				self.stop_live_tasks()

		except Exception as e:
			error = Error(
				message=str(e),
				traceback=' '.join(traceback.format_exception(e, value=e, tb=e.__traceback__)),
				_source=self.config.name,
				_uuid=str(uuid.uuid4())
			)
			self.results.append(error)
			self.results_count += 1
			self.uuids.append(error._uuid)
			self._print_item(error)
			yield error

		# Filter results and log info
		self.mark_duplicates()
		self.results = self.filter_results()
		self.log_results()
		self.run_hooks('on_end')

	def _print_item(self, item):
		item_str = self.get_repr(item)
		if self.print_remote_status or DEBUG > 1:
			item_str += rich_to_ansi(f' \[[dim]{item._source}[/]]')
		if self.print_item and isinstance(item, (OutputType, DotMap)):
			if self.print_json:
				self._print(item, out=sys.stdout)
			elif self.print_raw:
				self._print(str(item), out=sys.stdout)
			else:
				self._print(item_str, out=sys.stdout)
			self.output += item_str + '\n' if isinstance(item, OutputType) else str(item) + '\n'
		elif self.print_line and isinstance(item, str):
			self._print(item, out=sys.stderr, end='\n')

	def mark_duplicates(self):
		debug('running duplicate check', id=self.config.name, sub='runner.mark_duplicates')
		dupe_count = 0
		for item in self.results:
			debug('running duplicate check', obj=item.toDict(), obj_breaklines=True, sub='runner.mark_duplicates', level=5)  # noqa: E501
			others = [f for f in self.results if f == item and f._uuid != item._uuid]
			if others:
				main = max(item, *others)
				dupes = [f for f in others if f._uuid != main._uuid]
				main._duplicate = False
				main._related.extend([dupe._uuid for dupe in dupes])
				main._related = list(dict.fromkeys(main._related))
				if main._uuid != item._uuid:
					debug(f'found {len(others)} duplicates for', obj=item.toDict(), obj_breaklines=True, sub='runner.mark_duplicates', level=5)  # noqa: E501
					item._duplicate = True
					item = self.run_hooks('on_item', item)
					if item._uuid not in main._related:
						main._related.append(item._uuid)
					main = self.run_hooks('on_duplicate', main)
					item = self.run_hooks('on_duplicate', item)

				for dupe in dupes:
					if not dupe._duplicate:
						debug(
							'found new duplicate', obj=dupe.toDict(), obj_breaklines=True,
							sub='runner.mark_duplicates', level=5)
						dupe_count += 1
						dupe._duplicate = True
						dupe = self.run_hooks('on_duplicate', dupe)

		duplicates = [repr(i) for i in self.results if i._duplicate]
		if duplicates:
			duplicates_str = '\n\t'.join(duplicates)
			debug(f'Duplicates ({dupe_count}):\n\t{duplicates_str}', sub='runner.mark_duplicates', level=5)
		debug(f'duplicate check completed: {dupe_count} found', id=self.config.name, sub='runner.mark_duplicates')

	def yielder(self):
		raise NotImplementedError()

	def toDict(self):
		return {
			'config': self.config.toDict(),
			'opts': self.config.supported_opts,
			'name': self.name,
			'targets': self.targets,
			'run_opts': self.run_opts,
			'parent': self.parent,
			'has_children': self.has_children,
			'chunk': self.chunk,
			'chunk_count': self.chunk_count,
			'results_count': self.results_count,
			'sync': self.sync,
			'done': self.done,
			'output': self.output,
			'status': self.status,
			'progress': self.progress,
			'start_time': self.start_time,
			'end_time': self.end_time,
			'last_updated': self.last_updated,
			'elapsed': self.elapsed.total_seconds(),
			'elapsed_human': self.elapsed_human,
			'errors': self.errors,
			'context': self.context
		}

	def run_hooks(self, hook_type, *args):
		result = args[0] if len(args) > 0 else None
		if not self.enable_hooks:
			return result
		for hook in self.hooks[hook_type]:
			name = f'{self.__class__.__name__}.{hook_type}'
			fun = self.get_func_path(hook)
			try:
				_id = self.context.get('task_id', '') or self.context.get('workflow_id', '') or self.context.get('scan_id', '')
				debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'started'}, id=_id, sub='hooks', level=3)
				result = hook(self, *args)
				debug('', obj={name + ' [dim yellow]->[/] ' + fun: 'ended'}, id=_id, sub='hooks', level=3)
			except Exception as e:
				if self.raise_on_error:
					raise e
				else:
					if DEBUG > 1:
						logger.exception(e)
					else:
						self._print(
							f'{fun} failed: "{e.__class__.__name__}: {str(e)}". Skipping',
							color='bold red',
							rich=True)
						self._print('Set DEBUG to > 1 to see the detailed exception.', color='dim red', rich=True)
		return result

	def run_validators(self, validator_type, *args):
		# logger.debug(f'Running validators of type {validator_type}')
		for validator in self.validators[validator_type]:
			# logger.debug(validator)
			if not validator(self, *args):
				if validator_type == 'input':
					self._print(f'{validator.__doc__}', color='bold red', rich=True)
				return False
		return True

	@staticmethod
	def resolve_exporters(exporters):
		"""Resolve exporters from output options."""
		if not exporters or exporters in ['false', 'False']:
			return []
		if isinstance(exporters, str):
			exporters = exporters.split(',')
		classes = [
			import_dynamic(f'secator.exporters.{o.capitalize()}Exporter', 'Exporter')
			for o in exporters
			if o
		]
		return [cls for cls in classes if cls]

	def log_start(self):
		"""Log runner start."""
		remote_str = 'starting' if self.sync else 'sent to Celery worker'
		runner_name = self.__class__.__name__
		self.log_header()
		self._print(
			f':tada: {runner_name} [bold magenta]{self.config.name}[/] {remote_str}...', rich=True)
		if not self.sync and self.print_remote_status and self.__class__.__name__ != 'Scan':
			self._print('\n🏆 [bold gold3]Live results:[/]', rich=True)

	def log_header(self):
		"""Log runner header."""
		runner_name = self.__class__.__name__

		# Description
		panel_str = f':scroll: [bold gold3]Description:[/] {self.config.description}'

		# Workspace
		if self.workspace_name:
			panel_str += f'\n:construction_worker: [bold gold3]Workspace:[/] {self.workspace_name}'

		# Targets
		if self.targets:
			panel_str += '\n:pear: [bold gold3]Targets:[/]'
			for target in self.targets:
				panel_str += f'\n   • {target}'

		# Options
		DISPLAY_OPTS_EXCLUDE = [
			'sync', 'worker', 'debug', 'output', 'json', 'orig', 'raw', 'format', 'quiet'
		]
		items = [
			f'[italic]{k}[/]: {v}'
			for k, v in self.run_opts.items()
			if k not in DISPLAY_OPTS_EXCLUDE
			and v is not None
		]
		if items:
			panel_str += '\n:pushpin: [bold gold3]Options:[/]'
			for item in items:
				panel_str += f'\n   • {item}'

		if self.exporters:
			panel_str += '\n:email:  [bold gold3]Exporters:[/]'
			for exporter in self.exporters:
				exporter_name = exporter.__name__.replace('Exporter', '').lower()
				panel_str += f'\n   • {exporter_name}'

		panel = Panel(
			panel_str,
			title=f'[bold gold3]{runner_name}[/] [bold magenta]{self.config.name}[/]',
			border_style='bold gold3',
			expand=False,
			highlight=True
		)
		self._print('\n')
		self._print(panel, rich=True)

	def log_results(self):
		"""Log results.

		Args:
			results (list): List of results.
			output_types (list): List of result types to add to report.
		"""
		self.done = True
		self.progress = 100
		self.results_count = len(self.results)
		self.status = 'SUCCESS' if not self.errors else 'FAILURE'
		self.end_time = datetime.fromtimestamp(time())

		# Log execution results
		status = 'succeeded' if not self.errors else '[bold red]failed[/]'
		if self.print_run_summary:
			self._print('\n')
			self._print(
				f':tada: [bold green]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.config.name}[/] '
				f'[bold green]{status} in[/] [bold gold3]{self.elapsed_human}[/].', rich=True)

		# Log runner infos
		self.infos = [c for c in self.results if c._type == 'info']
		if self.infos:
			self._print(
				f':heavy_check_mark: [bold magenta]{self.config.name}[/] infos ({len(self.infos)}):',
				color='bold green', rich=True)
			for info in self.infos:
				self._print(f'   • \[{info._source}] {info.message}', color='bold green', rich=True)

		# Log runner errors
		self.errors = [c for c in self.results if c._type == 'error']
		if self.errors and self.print_errors:
			self._print(
				f':exclamation_mark:[bold magenta]{self.config.name}[/] errors ({len(self.errors)}):',
				color='bold red', rich=True)
			for error in self.errors:
				self._print(f'   • \[{error._source}] {error.message}', color='bold red', rich=True)

		# Build and send report
		if self.results:
			report = Report(self, exporters=self.exporters)
			report.build()
			report.send()
			self.report = report

		# Log results count
		if self.print_item_count and not self.print_raw and not self.orig:
			count_map = self._get_results_count()
			if all(count == 0 for count in count_map.values()):
				self._print(':exclamation_mark:Found 0 results.', color='bold red', rich=True)
			else:
				results_str = ':heavy_check_mark: Found ' + ' and '.join([
					f'{count} {pluralize(name) if count > 1 or count == 0 else name}'
					for name, count in count_map.items()
				]) + '.'
				self._print(results_str, color='bold green', rich=True)

	def stop_live_tasks(self):
		"""Stop all tasks running in Celery worker."""
		from secator.celery import revoke_task
		task_ids = []
		CeleryData.get_task_ids(self.celery_result, ids=task_ids)
		all_ids = list(set(task_ids + self.celery_ids))
		debug(f'stopping task ids: {all_ids}', sub='celery.state')
		for task_id in all_ids:
			data = CeleryData.get_task_data(task_id)
			if not data:
				data = {'id': task_id}
			revoke_task(data)

	def filter_results(self):
		"""Filter runner results using extractors defined in config."""
		extractors = self.config.results
		results = []
		if extractors:
			# Keep results based on extractors
			opts = merge_opts(self.config.options, self.run_opts)
			for extractor in extractors:
				tmp = process_extractor(self.results, extractor, ctx=opts)
				results.extend(tmp)

			# Keep the field types in results not specified in the extractors.
			extract_fields = [e['type'] for e in extractors]
			keep_fields = [
				_type for _type in OUTPUT_TYPES if _type.__name__ != 'Progress'
				if _type not in extract_fields
			]
			results.extend([
				item for item in self.results
				if item._type in keep_fields
			])
		else:
			results = self.results
		return results

	def _convert_item_schema(self, item):
		"""Convert dict item to a new structure using the class output schema.

		Args:
			item (dict): Item.

		Returns:
			dict: Item with new schema.
		"""
		# Load item using available output types and get the first matching
		# output type based on the schema
		new_item = None
		output_types = getattr(self, 'output_types', [])
		debug(f'Input item: {item}', sub='klass.load', level=5)

		# Skip if already converted
		if isinstance(item, DotMap) or isinstance(item, OutputType):
			return item

		# Use output discriminator to let user arbiter between output types to pick
		output_discriminator = getattr(self, 'output_discriminator', None)
		if output_discriminator:
			result = output_discriminator(item)
			if result:
				debug(f'Discriminated output type: {result.__name__}', sub='klass.load', level=5)
				output_types = [result]
			else:
				new_item = DotMap(item)
				new_item._type = 'unknown'
				return new_item

		debug(f'Output types to try: {[o.__name__ for o in output_types]}', sub='klass.load', level=5)
		for klass in output_types:
			debug(f'Loading item as {klass.__name__}', sub='klass.load', level=5)
			output_map = getattr(self, 'output_map', {})
			output_map = output_map.get(klass, {})
			try:
				new_item = klass.load(item, output_map)
				debug(f'[dim green]Successfully loaded item as {klass.__name__}[/]', sub='klass.load', level=5)
				break  # found an item that fits
			except (TypeError, KeyError) as e:  # can't load using class
				debug(
					f'[dim red]Failed loading item as {klass.__name__}: {type(e).__name__}: {str(e)}.[/] [dim green]Continuing.[/]',
					sub='klass.load',
					level=5)
				if DEBUG == 6:
					console.print_exception(show_locals=False)
				continue

		# No output type was found, so make no conversion
		if not new_item:
			new_item = DotMap(item)
			new_item._type = 'unknown'

		return new_item

	def _print(self, data, color=None, out=sys.stderr, rich=False, end='\n'):
		"""Print function.

		Args:
			data (str or dict): Input data.
			color (str, Optional): Rich color.
			out (str, Optional): Output pipe (sys.stderr, sys.stdout, ...)
			rich (bool, Optional): Force rich output.
		"""
		# Print a JSON item
		if isinstance(data, (OutputType, DotMap, dict)):
			if getattr(data, 'toDict', None):
				data = data.toDict()
			data = json.dumps(data)
			data = f'{self.prefix:>15} {data}' if self.prefix and not self.print_item else data

		if self.sync or rich:
			_console = console_stdout if out == sys.stdout else console
			_console.print(data, highlight=False, style=color, soft_wrap=True, end=end)
		else:
			print(data, file=out)

		# # Print a line using Rich console
		# if rich:
		# 	_console = console_stdout if out == sys.stdout else console
		# 	_console.print(data, highlight=False, style=color, soft_wrap=True)

		# # Print a line using Rich markup
		# elif markup:
		# 	from rich import print as _print
		# 	from rich.text import Text
		# 	_print(Text.from_markup(data), file=out)

		# # Print a line raw
		# else:
		# 	print(data, file=out)

	def _set_print_prefix(self):
		self.prefix = ''
		if self.print_cmd_prefix:
			self.prefix = f'[bold gold3]({self.config.name})[/]'
		if self.chunk and self.chunk_count:
			self.prefix += f' [{self.chunk}/{self.chunk_count}]'

	def _get_results_count(self):
		count_map = {}
		for output_type in self.output_types:
			if output_type.__name__ == 'Progress':
				continue
			name = output_type.get_name()
			count = len([r for r in self.results if r._type == name])
			count_map[name] = count
		return count_map

	def _process_item(self, item: dict):
		# Run item validators
		if not self.run_validators('item', item):
			return None

		# Convert output dict to another schema
		if isinstance(item, dict):
			item = self.run_hooks('on_item_pre_convert', item)
			if not item:
				return None
			if not self.orig:
				item = self._convert_item_schema(item)
			else:
				item = DotMap(item)

		if isinstance(item, dict) and not self.orig:
			item = self._convert_item_schema(item)
		elif isinstance(item, OutputType):
			pass
		else:
			item = DotMap(item)

		# Update item context
		item._context.update(self.context)

		# Add context, uuid, progress to item
		if not item._source:
			item._source = self.config.name

		if not item._uuid:
			item._uuid = str(uuid.uuid4())

		if item._type == 'progress' and item._source == self.config.name:
			self.progress = item.percent
			update_frequency = CONFIG.runners.progress_update_frequency
			if self.last_updated_progress and (item._timestamp - self.last_updated_progress) < update_frequency:
				return None
			elif int(item.percent) in [0, 100]:
				return None
			else:
				self.last_updated_progress = item._timestamp

		# Run on_item hooks
		if isinstance(item, OutputType) and not self.orig:
			item = self.run_hooks('on_item', item)

		return item

	def get_repr(self, item=None):
		if not item:
			return [
				self.get_repr(item)
				for item in self.results
			]
		if self.output_fmt:
			item = self.output_fmt.format(**item.toDict())
		elif isinstance(item, OutputType):
			item = repr(item)
		return item

	@classmethod
	def get_func_path(cls, func):
		"""
		Get the full symbolic path of a function or method, including staticmethods,
		using function and method attributes.

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
