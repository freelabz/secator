from contextlib import nullcontext
from datetime import datetime
from time import sleep, time

import humanize
from celery.result import AsyncResult
from fp.fp import FreeProxy
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (Progress, SpinnerColumn, TextColumn,
						   TimeElapsedColumn)

from secsy.definitions import DEBUG, DEFAULT_PROXY_TIMEOUT, OPT_NOT_SUPPORTED
from secsy.output_types import OUTPUT_TYPES, OutputType
from secsy.report import Report
from secsy.rich import console, console_stdout
from secsy.runners._helpers import (get_task_ids, get_task_info,
									process_extractor)
from secsy.utils import import_dynamic, merge_opts, get_file_timestamp, pluralize, print_results_table
from dotmap import DotMap
import json
import sys
import logging


logger = logging.getLogger(__name__)

HOOKS = [
	'on_init',
	'on_start',
	'on_end',
	'on_item_pre_convert',
	'on_item',
	'on_line',
	'on_iter',
	'on_error'
]

VALIDATORS = [
	'input',
	'item'
]

class Runner:
	"""Runner class.

	Args:
		config (secsy.config.ConfigLoader): Loaded config.
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

	def __init__(self, config, targets, results=[], workspace_name=None, run_opts={}, hooks={}, context={}):
		self.config = config
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.results = results
		self.results_count = 0
		self.workspace_name = workspace_name
		self.run_opts = run_opts.copy()
		self.sync = run_opts.get('sync', True)
		self.exporters = self.resolve_exporters()
		self.done = False
		self.start_time = datetime.fromtimestamp(time())
		self.end_time = None
		self.errors = []
		self.output = ''
		self.status = 'RUNNING'
		self.progress = 0
		self.context = context
		self.hooks = hooks
		self.delay = run_opts.get('delay', False)
		self.uuids = []

		# Proxy config (global)
		self.proxy = self.run_opts.get('proxy', False)
		self.configure_proxy()

		# Process input
		self.input = input
		if isinstance(self.input, list) and len(self.input) == 1:
			self.input = self.input[0]

		# Yield dicts if CLI supports JSON
		if self.output_return_type is dict or (self.json_flag is not None):
			self.output_return_type = dict

		# Print options
		self.print_timestamp = self.run_opts.get('print_timestamp', False)
		self.print_item = self.run_opts.get('print_item', False)
		self.print_line = self.run_opts.get('print_line', False)
		self.print_item_count = self.run_opts.get('print_item_count', False)
		self.print_cmd = self.run_opts.get('print_cmd', False)
		self.print_progress = self.run_opts.get('print_progress', True)
		self.print_cmd_prefix = self.run_opts.get('print_cmd_prefix', False)
		self.print_live_status = self.run_opts.get('print_live_status', False)
		self.print_results = self.run_opts.get('print_results', False)

		# Output options
		self.output_raw = self.run_opts.get('raw', False)
		self.output_fmt = self.run_opts.get('format', False)
		self.output_table = self.run_opts.get('table', False)
		self.output_orig = self.run_opts.get('orig', False)
		self.output_color = self.run_opts.get('color', False)
		self.output_quiet = self.run_opts.get('quiet', False)
		_json = self.run_opts.get('json', True) or self.output_table or self.output_raw

		# Library output
		self.raw_yield = self.run_opts.get('raw_yield', False)

		# Determine if JSON output or not
		self.output_json = self.output_return_type == dict
		if self.print_timestamp and not _json:
			self.output_json = False

		# Hooks
		self.hooks = {name: [] for name in HOOKS}
		hooks = self.run_opts.get('hooks', {})
		for key in self.hooks:
			instance_func = getattr(self, key, None)
			if instance_func:
				self.hooks[key].append(instance_func)
			self.hooks[key].extend(hooks.get(key, []))
			self.hooks[key].extend(self.hooks.get(self.__class__, {}).get(key, []))

		# Validators
		self.validators = {name: [] for name in VALIDATORS}
		validators = self.run_opts.get('validators', {})
		for key in self.validators:
			instance_func = getattr(self, f'validate_{key}', None)
			if instance_func:
				self.validators[key].append(instance_func)
			self.validators[key].extend(validators.get(key, []))
			self.validators[key].extend(self.validators.get(self.__class__, {}).get(key, []))

		# Chunks
		self.chunk = self.run_opts.get('chunk', None)
		self.chunk_count = self.run_opts.get('chunk_count', None)
		self._set_print_prefix()

		# Abort if inputs are invalid
		self.input_valid = True
		if not self.run_validators('input', self.input):
			self.run_hooks('on_end')
			self.input_valid = False

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
		if self.__class__.__name__ in ['Runner', 'Scan']:
			self.log_start()

		if not self.input_valid:
			return

		for item in self.yielder():

			if isinstance(item, OutputType):
				if item._uuid in self.uuids:
					continue
				self.results.append(item)
				self.uuids.append(item._uuid)
				self.results_count += 1
				yield item

			elif isinstance(item, dict):
				item = self._process_item(item)
				if not item or item._uuid in self.uuids:
					continue
				yield item

			elif isinstance(item, str):
				if self.print_line and not self.output_quiet:
					self._print(item, out=sys.stderr, ignore_raw=True)

				if self.output_return_type is not dict:
					self.results.append(item)
					yield item

			if item:
				self.output += str(item) + '\n'

			self.run_hooks('on_iter')

		# Filter results and log info
		self.results = self.filter_results()
		if self.print_results:
			self.log_results()
		self.run_hooks('on_end')

	def yielder(self):
		raise NotImplementedError()

	def toDict(self):
		return {
			'config': self.config.toDict(),
			'targets': self.targets,
			'run_opts': self.run_opts,
			'workspace_name': self.workspace_name,
			'results_count': self.results_count,
			'sync': self.sync,
			'done': self.done,
			'status': self.status,
			'progress': self.progress,
			'start_time': self.start_time,
			'end_time': self.end_time,
			'elapsed_human': self.elapsed_human,
			'errors': self.errors,
			'context': self.context
		}

	def configure_proxy(self):
		"""Configure proxy. Start with global settings like 'proxychains' or 'random', or fallback to tool-specific
		proxy settings.

		TODO: Move this to a subclass of Command, or to a configurable attribute to pass to derived classes as it's not
		related to core functionality.
		"""
		opt_key_map = getattr(self, 'opt_key_map', {})
		proxy_opt = opt_key_map.get('proxy', False)
		support_proxychains = getattr(self, 'proxychains', True)
		proxychains_flavor = getattr(self, 'proxychains_flavor', 'proxychains')
		support_proxy = proxy_opt and proxy_opt != OPT_NOT_SUPPORTED
		if self.proxy == 'proxychains':
			if not support_proxychains:
				return
			self.cmd = f'{proxychains_flavor} {self.cmd}'
		elif self.proxy and support_proxy:
			if self.proxy == 'random':
				self.run_opts['proxy'] = FreeProxy(timeout=DEFAULT_PROXY_TIMEOUT, rand=True, anonym=True).get()
			else:  # tool-specific proxy settings
				self.run_opts['proxy'] = self.proxy

	def run_hooks(self, hook_type, *args):
		# logger.debug(f'Running hooks of type {hook_type}')
		result = args[0] if len(args) > 0 else None
		for hook in self.hooks[hook_type]:
			# logger.debug(hook)
			result = hook(self, *args)
		return result

	def run_validators(self, validator_type, *args):
		# logger.debug(f'Running validators of type {validator_type}')
		for validator in self.validators[validator_type]:
			# logger.debug(validator)
			if not validator(self, *args):
				if validator_type == 'input':
					self._print(f'{validator.__doc__}', color='bold red')
				return False
		return True

	def resolve_exporters(self):
		"""Resolve exporters from output options."""
		output = self.run_opts.get('output', None)
		if output is None:
			return self.default_exporters
		elif output is False:
			return []
		exporters = [
			import_dynamic(f'secsy.exporters.{o.capitalize()}Exporter', 'Exporter')
			for o in output.split(',')
			if o
		]
		return [e for e in exporters if e]

	def log_start(self):
		"""Log runner start."""
		remote_str = 'starting' if self.sync else 'sent to Celery worker'
		runner_name = self.__class__.__name__
		self.log_header()
		self._print(
			f':tada: {runner_name} [bold magenta]{self.config.name}[/] {remote_str}...')

	def log_header(self):
		"""Log runner header."""
		runner_name = self.__class__.__name__
		opts = merge_opts(self.config.options, self.run_opts)

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
			'sync', 'worker', 'debug', 'output', 'json', 'orig', 'raw', 'format', 'color', 'table', 'quiet', 'raw_yield'
		]
		items = [
			f'[italic]{k}[/]: {v}'
			for k, v in opts.items()
			if not k.startswith('print_') and k not in DISPLAY_OPTS_EXCLUDE
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
		self._print(panel)

	def log_results(self):
		"""Log results.

		Args:
			results (list): List of results.
			output_types (list): List of result types to add to report.
		"""
		self.done = True
		self.progress = 100
		self.results_count = len(self.results)
		self.status = 'SUCCESS' if not self.errors else 'FAILED'
		self.end_time = datetime.fromtimestamp(time())
		self._process_results()
		self.run_hooks('on_end')

		# Log runner errors
		for error in self.errors:
			self._print(error, color='bold red')

		# Build and send report
		if self.results:
			report = Report(self, exporters=self.exporters)
			report.build()
			report.send()
			self.report = report
		else:
			self._print('No results found.', color='bold red')

		# Log execution results
		self._print(
			f'\n:tada: [bold green]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.config.name}[/] '
			f'[bold green]finished successfully in[/] [bold gold3]{self.elapsed_human}[/].')

	@staticmethod
	def get_live_results(result):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and partial results from each task that runs.

		Args:
			result (celery.result.AsyncResult): Result object.

		Yields:
			dict: Subtasks state and results.
		"""
		res = AsyncResult(result.id)
		while True:
			task_ids = []
			get_task_ids(result, ids=task_ids)
			for task_id in task_ids:
				info = get_task_info(task_id)
				if not info:
					continue
				yield info

			# Break out of while loop
			if res.ready():
				break

			# Sleep between updates
			sleep(1)

	def process_live_tasks(self, result, description=True, results_only=True, print_live_status=True):
		"""Rich progress indicator showing live tasks statuses.

		Args:
			result (AsyncResult | GroupResult): Celery result.
			results_only (bool): Yield only results, no task state.

		Yields:
			dict: Subtasks state and results.
		"""
		config_name = self.config.name
		runner_name = self.__class__.__name__.capitalize()

		# Display live results if print_live_status is set
		if print_live_status:
			class PanelProgress(Progress):
				def get_renderables(self):
					yield Padding(Panel(
						self.make_tasks_table(self.tasks),
						title=f'[bold gold3]{runner_name}[/] [bold magenta]{config_name}[/] tasks',
						border_style='bold gold3',
						expand=False,
						highlight=True), pad=(2, 0, 0, 0))

			tasks_progress = PanelProgress(
				SpinnerColumn('dots'),
				TextColumn('{task.fields[descr]}  ') if description else '',
				TextColumn('[bold cyan]{task.fields[name]}[/]'),
				TextColumn('[dim gold3]{task.fields[chunk_info]}[/]'),
				TextColumn('{task.fields[state]:<20}'),
				TimeElapsedColumn(),
				TextColumn('{task.fields[count]}'),
				# TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),  # noqa: W605
				refresh_per_second=1
			)
			state_colors = {
				'RUNNING': 'bold yellow',
				'SUCCESS': 'bold green',
				'FAILURE': 'bold red',
				'REVOKED': 'bold magenta'
			}
		else:
			tasks_progress = nullcontext()

		with tasks_progress as progress:

			# Make progress tasks
			tasks_progress = {}

			# Get live results and print progress
			for info in Runner.get_live_results(result):

				# Re-yield so that we can consume it externally
				if results_only:
					yield from info['results']
				else:
					yield info

				if not print_live_status:
					continue

 				# Ignore partials in output unless DEBUG > 1
				# TODO: weird to change behavior based on debug flag, could cause issues
				if info['chunk'] and not DEBUG > 1:
					continue

				# Handle error if any
				# TODO: error handling should be moved to process_live_tasks
				state = info['state']
				if info['error']:
					state = 'FAILURE'
					error = 'Error in task {name} {chunk_info}:\n{error}'.format(**info)
					if error not in self.errors:
						self.errors.append(error)

				task_id = info['id']
				state_str = f'[{state_colors[state]}]{state}[/]'
				info['state'] = state_str

				if task_id not in tasks_progress:
					id = progress.add_task('', **info)
					tasks_progress[task_id] = id
				else:
					progress_id = tasks_progress[task_id]
					if state in ['SUCCESS', 'FAILURE']:
						progress.update(progress_id, advance=100, **info)

			# Update all tasks to 100 %
			for progress_id in tasks_progress.values():
				progress.update(progress_id, advance=100)

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
				_type for _type in OUTPUT_TYPES
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
		for klass in output_types:
			output_map = getattr(self, 'output_map', {})
			output_map = output_map.get(klass, {})
			try:
				new_item = klass.load(item, output_map)
				break  # found an item that fits
			except (TypeError, KeyError):  # can't load using class
				# logger.debug(f'Failed loading item with {klass}: {str(e)}. Continuing')
				continue

		# No output type was found, so make no conversion
		if not new_item:
			new_item = DotMap(item)
			new_item._type = 'unknown'

		# Add source to item
		new_item._source = self.config.name

		# Add context to item
		new_item._context = self.context

		# If progress item, update task progress
		if new_item._type == 'progress':
			self.progress = new_item.percent

		return new_item
	

	def _print(self, data, color=None, out=sys.stderr, ignore_raw=False, ignore_log=False):
		"""Print function.

		Args:
			data (str or dict): Input data.
			color (str, Optional): Termcolor color.
			out (str, Optional): Output pipe (sys.stderr, sys.stdout, ...)
			ignore_raw (bool, Optional): Ignore raw mode.
			ignore_log (bool, Optional): Ignore log stamps.
		"""
		# Choose rich console
		_console = console_stdout if out == sys.stdout else console
		log_json = console.print_json
		log = console.log if self.print_timestamp else _console.print

		# Print a rich table
		if self.output_table and isinstance(data, list) and isinstance(data[0], (OutputType, DotMap, dict)):
			print_results_table(self.results)

		# Print a JSON item
		elif isinstance(data, (OutputType, DotMap, dict)):
			# If object has a 'toDict' method, use it
			if getattr(data, 'toDict', None):
				data = data.toDict()

			# JSON dumps data so that it's consumable by other commands
			data = json.dumps(data)

			# Add prefix to output
			data = f'{self.prefix:>15} {data}' if self.prefix and not self.print_item else data

			# We might want to parse results with e.g 'jq' so we need pure JSON line with no logging info clarifies the
			# user intent to use it for visualizing results.
			log_json(data) if self.output_color and self.print_item else _console.print(data, highlight=False)

		# Print a line
		else:
			# If orig mode (--orig) or raw mode (--raw), we might want to parse results with e.g pipe redirections, so
			# we need a pure line with no logging info.
			if ignore_log or (not ignore_raw and (self.output_orig or self.output_raw)):
				data = f'{self.prefix} {data}' if self.prefix and not self.print_item else data
				_console.print(data, highlight=False, style=color)
			else:
				# data = escape(data)
				# data = Text.from_ansi(data)
				if color:
					data = f'[{color}]{data}[/]'
				data = f'{self.prefix} {data}' if self.prefix else data
				try:
					log(data)
				except:  # noqa: E722
					print(data)

	def _set_print_prefix(self):
		self.prefix = ''
		if self.print_cmd_prefix:
			self.prefix = f'[bold gold3]({self.name})[/]'
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

	def _process_results(self):
		# TODO: this is only for logging timestamp to show up properly !!!
		if self.print_timestamp:
			sleep(1)

		# Log results count
		if self.print_item_count and self.output_json and not self.output_raw and not self.output_orig:
			count_map = self._get_results_count()
			if all(count == 0 for count in count_map.values()):
				self._print(':adhesive_bandage: Found 0 results.', color='bold red')
			else:
				results_str = ':pill: Found ' + ' and '.join([
					f'{count} {pluralize(name) if count > 1 or count == 0 else name}'
					for name, count in count_map.items()
				]) + '.'
				self._print(results_str, color='bold green')

		# Print table if in table mode
		if self.output_table and self.results and len(self.results) > 0:
			if isinstance(self.results[0], str):
				self._print('\n'.join(self.results))
			else:
				self._print(self.results, out=sys.stdout)

	def _process_item(self, item: dict):
		# Run item validators
		if not self.run_validators('item', item):
			return None

		# Run item hooks
		item = self.run_hooks('on_item_pre_convert', item)
		if not item:
			return None

		# Convert output dict to another schema
		if not self.output_orig:
			item = self._convert_item_schema(item)

			# Run item convert hooks
			item = self.run_hooks('on_item', item)
		else:
			item = DotMap(item)

		# Get item klass
		item_klass = item.__class__.__name__

		# Add item to result
		if not item_klass == 'Progress':
			self.results.append(item)
			self.results_count += 1

		# Item to print
		item_str = item

		# In raw mode, print principal key or output format field.
		if self.output_raw:
			item_str = self._rawify(item)

		# In raw yield mode, extract principal key from dict (default 'on' for library usage)
		if self.raw_yield:
			item = self._rawify(item)
			item_str = item

		# Print item to console or log
		if item_klass == 'Progress' and self.print_progress:
			self._print(str(item_str), out=sys.stderr, ignore_log=True, color='dim cyan')
			item = None

		elif self.print_item and self.output_json and not self.output_table:
			self._print(item_str, out=sys.stdout)

		# Return item
		return item

	def _rawify(self, item=None):
		if not item:
			return [
				self._rawify(item)
				for item in self.results
			]
		if self.output_raw:
			if self.output_fmt:
				item = self.output_fmt.format(**item)
			elif isinstance(item, OutputType):
				item = str(item)
		return item