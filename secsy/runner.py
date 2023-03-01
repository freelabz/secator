import logging
import os
from datetime import datetime
from time import sleep, time

import humanize
from celery import chain, chord
from celery.result import AsyncResult, GroupResult
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import (Progress, SpinnerColumn, TextColumn,
							TimeElapsedColumn)
from secsy.config import ConfigLoader
from secsy.definitions import OUTPUT_TYPES, RECORD, REPORTS_FOLDER
from secsy.rich import build_table, console
from secsy.utils import deduplicate, get_command_cls, merge_opts, pluralize

logger = logging.getLogger(__name__)


class Runner:

	def __init__(self, config, targets, **run_opts):
		self.config = config
		self.run_opts = run_opts
		self.done = False
		self.results = []
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.start_time = datetime.fromtimestamp(time())

	def log_results(self):
		"""Log results.

		Args:
			results (list): List of results.
			output_types (list): List of result types to add to report.
		"""
		if not self.results:
			return
		render = Console(record=True)
		render.print()
		title = f'{self.__class__.__name__} "{self.config.name}" results'
		h1 = Markdown(f'# {title}')
		render.print(h1, style='bold magenta', width=50)
		render.print()
		for output_type in OUTPUT_TYPES:
			sort_by, output_fields = get_table_fields(output_type)
			items = [item for item in self.results if item['_type'] == output_type]
			if items:
				_table = build_table(items, output_fields, sort_by)
				_type = pluralize(items[0]['_type'])
				render.print(_type.upper(), style='bold gold3', justify='left')
				render.print(_table)
				render.print()

		# Make HTML report
		timestr = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
		html_title = title.replace(' ', '_').lower()
		os.makedirs(REPORTS_FOLDER, exist_ok=True)
		html_path = f'{REPORTS_FOLDER}/{html_title}_{timestr}.html'
		render.save_html(html_path)
		console.log(f'Saved HTML report to {html_path}')

		# Log execution results
		self.end_time = datetime.fromtimestamp(time())
		delta = self.end_time - self.start_time
		delta_str = humanize.naturaldelta(delta)
		console.print(f':tada: [bold green]Workflow[/] [bold magenta]{self.config.name}[/] [bold green]finished successfully in[/] [bold gold3]{delta_str}[/].')
		console.print()


class Scan(Runner):
	def __init__(self, config, targets, **run_opts):
		self.config = config
		self.run_opts = run_opts
		self.done = False
		self.results = []
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets

	def run(self, sync=True, results=[]):
		"""Run scan.

		Yields:
			dict: Item yielded from individual workflow tasks.
		"""
		# Add target to results
		self.results = results + [
			{'name': name, '_source': 'scan', '_type': 'target'}
			for name in self.targets
		]
		self.results = results

		# Run workflows
		for name, conf in self.config.workflows.items():

			# Extract opts and and expand target from previous workflows results
			targets, conf = merge_extracted_values(self.results, conf or {})
			if not targets:
				targets = self.targets

			# Merge run options
			run_opts = conf
			run_opts.update(self.run_opts)

			# Run workflow
			wresults = run_workflow(
				name,
				targets,
				sync=sync,
				results=self.results,
				**run_opts)
			self.results.extend(wresults)

		self.log_results()
		return self.results


class Workflow(Runner):
	"""Workflow runner.

	Args:
		config (secsy.config.ConfigLoader): Loaded config.
		targets (list): List of targets to run workflow on.
		run_opts (dict): Run options.

	Yields:
		dict: Result (when running in sync mode with `run`).

	Returns:
		list: List of results (when running in async mode with `run_async`).
	"""

	def __init__(self, config, targets, **run_opts):
		self.config = config
		self.run_opts = run_opts
		self.done = False
		self.results = []
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets

	def run(self, sync=True, results=[], show_results=True):
		"""Run workflow.

		Args:
			sync (bool): Run in sync mode (main thread). If False, run in Celery 
				worker in distributed mode.

		Returns:
			list: List of results.
		"""
		self.show_results = show_results
		self.sync = sync
		if sync:
			fmt_opts = {
				'print_timestamp': True,
				'print_cmd': True,
				'print_item_count': True,
			}
		else:
			fmt_opts = {
				'print_timestamp': False,
				'print_cmd': True,
				'print_cmd_prefix': True,
				'print_item_count': True,
			}
		fmt_opts['sync'] = sync
		fmt_opts['track'] = True
		self.config.options.update(fmt_opts)

		# Log workflow start
		self.log_start()

		# Add target to results
		self.results = results + [
			{'name': name, '_source': 'workflow', '_type': 'target'}
			for name in self.targets
		]

		# Build Celery workflow
		workflow = self.build_celery_workflow(results=results)

		# Run Celery workflow and get results
		if sync:
			with console.status(f'[bold yellow]Running workflow [bold magenta]{self.config.name} ...'):
				result = workflow.apply()
		else:
			result = workflow()
			console.log(f'Celery workflow [bold magenta]{str(result)}[/] sent to broker.')
			self.process_live_tasks(result)
		self.results = result.get(propagate=False)
		self.results = self.filter_results()
		self.done = True
		self.log_workflow()
		return self.results

	def process_live_tasks(self, result):
		tasks_progress = Progress(
			SpinnerColumn('dots'),
			TextColumn('[bold gold3]{task.fields[name]}[/]'),
			TextColumn('{task.fields[state]:<20}'),
			TimeElapsedColumn(),
			TextColumn('{task.fields[count]}'),
			TextColumn('\[[bold magenta]{task.fields[celery_task_id]:<30}[/]]'),
			refresh_per_second=1
		)
		state_colors = {
			'RUNNING': 'bold yellow',
			'SUCCESS': 'bold green',
			'FAILURE': 'bold red',
			'REVOKED': 'bold magenta'
		}
		errors = []
		with tasks_progress as progress:

			# Make progress tasks
			tasks_progress = {}

			# Poll tasks for status
			while True:
				task_ids = []
				get_task_ids(result, ids=task_ids)
				for task_id in task_ids:
					info = get_task_info(task_id)
					if not info or not info['track']:
						continue
					state = info['state']
					state_str = f'[{state_colors[state]}]{state}[/]'
					info['state'] = state_str
					if task_id not in tasks_progress:
						id = progress.add_task('', **info)
						tasks_progress[task_id] = id
					else:
						progress_id = tasks_progress[task_id]
						if state in ['SUCCESS', 'FAILURE']:
							progress.update(progress_id, advance=100, **info)

					# Add error
					if state == 'FAILURE':
						error_str = f'[bold gold3]{info["name"]}[/]: [bold red]{info["error"]}[/]'
						if error_str not in errors:
							errors.append(error_str)

				# Update all tasks to 100 % if workflow has finished running
				res = AsyncResult(result.id)
				if res.ready():
					for progress_id in tasks_progress.values():
						progress.update(progress_id, advance=100)
					break

				# Sleep between updates
				sleep(1)
			
		if errors:
			console.print()
			console.log('Errors:', style='bold red')
			for error in errors:
				console.print('  ' + error)

	def filter_results(self):
		extractors = self.config.results
		results = []
		if extractors:
			# Keep results based on extractors
			for extractor in extractors:
				ctx = merge_opts(self.run_opts, self.config.options)
				tmp = process_extractor(self.results, extractor, ctx=ctx)
				results.extend(tmp)

			# Keep the field types in results not specified in the extractors.
			extract_fields = [e['type'] for e in extractors]
			keep_fields = [
				_type for _type in OUTPUT_TYPES
				if _type not in extract_fields
			]
			results.extend([
				item for item in self.results
				if item['_type'] in keep_fields
			])
		else:
			results = self.results
		return results

	def build_celery_workflow(self, results=[]):
		""""Build Celery workflow.

		Returns:
			celery.chain: Celery task chain.
		"""
		from secsy.celery import forward_results
		sigs = Workflow.get_tasks(
			self.config.tasks.toDict(),
			self.targets,
			self.config.options,
			self.run_opts)
		sigs = [forward_results.si(results)] + sigs + [forward_results.s()]
		workflow = chain(*sigs)
		return workflow

	@staticmethod
	def get_tasks(obj, targets, workflow_opts, run_opts):
		"""Get tasks recursively as Celery chains / chords.

		Args:
			obj (secsy.config.ConfigLoader): Config.
			targets (list): List of targets.
			workflow_opts (dict): Workflow options.
			run_opts (dict): Run options.
			sync (bool): Synchronous mode (chain of tasks, no chords).

		Returns:
			list: List of signatures.
		"""
		from secsy.celery import forward_results
		sigs = []
		for task_name, task_opts in obj.items():
			# Task opts can be None
			task_opts = task_opts or {}

			# If it's a group, process the sublevel tasks as a Celery chord.
			if task_name == '_group':
				tasks = Workflow.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts)
				sig = chord((tasks), forward_results.s())
			elif task_name == '_chain':
				tasks = Workflow.get_tasks(
					task_opts,
					targets,
					workflow_opts,
					run_opts
				)
				sig = chain(*tasks)
			else:
				# Get task class
				task = get_command_cls(task_name)

				# Merge task options (order of priority with overrides)
				opts = merge_opts(run_opts, workflow_opts, task_opts)

				# TODO: If the task doesn't support multiple input targets, split
				# TODO: add more split support for huge lists of URLs etc.
				# if task.file_flag is None and isinstance(_targets, list):
					# sig = group(task(targets, opts=opts).s() for input in target)
				# else:
				sig = task.s(targets, **opts)
			sigs.append(sig)
		return sigs

	def log_start(self):
		"""Log workflow start."""
		self.start_time = datetime.fromtimestamp(time())
		remote_str = 'starting' if self.sync else 'sent to [bold gold3]Celery[/] worker'
		console.print(f':tada: [bold green]Workflow[/] [bold magenta]{self.config.name}[/] [bold green]{remote_str}...[/]')
		self.log_workflow()

	def log_workflow(self):
		"""Log workflow."""
		# Print workflow options
		if not self.done:
			opts = merge_opts(self.run_opts, self.config.options)
			console.print()
			console.print(f'[bold gold3]Workflow:[/]    {self.config.name}')

			# Description
			description = self.config.description
			if description:
				console.print(f'[bold gold3]Description:[/] {description}')

			# Targets
			if self.targets:
				console.print('Targets: ', style='bold gold3')
				for target in self.targets:
					console.print(f' • {target}')

			# Options
			items = [
				f'[italic]{k}[/]: {v}'
				for k, v in opts.items() if v is not None
			]
			if items:
				console.print('Options:', style='bold gold3')
				for item in items:
					console.print(f' • {item}')
			
			console.print()

		# Print workflow results
		if self.show_results:
			self.log_results()

		if self.done:
			self.end_time = datetime.fromtimestamp(time())
			delta = self.end_time - self.start_time
			delta_str = humanize.naturaldelta(delta)
			console.print(f':tada: [bold green]Workflow[/] [bold magenta]{self.config.name}[/] [bold green]finished successfully in[/] [bold gold3]{delta_str}[/].')
			console.print()


def run_workflow(name, targets, sync=True, results=[], show_results=True, **run_opts):
	"""Run workflow.

	Args:
		name (str): Workflow name.
		targets (list): Targets.
		run_opts (dict): Run options.

	Yields:
		dict: Item yielded from individual workflow tasks.
	"""
	workflow = ConfigLoader(name=f'workflows/{name}')
	workflow = Workflow(workflow, targets, **run_opts)
	results = workflow.run(sync=sync, results=results, show_results=show_results)
	return results


def run_scan(name, targets, sync=True, results=[], **run_opts):
	"""Run scan.

	Args:
		name (str): Workflow name.
		targets (list): Targets.
		run_opts (dict): Run options.

	Yields:
		dict: Item yielded from individual workflow tasks.
	"""
	scan = ConfigLoader(name=f'scans/{name}')
	scan = Scan(scan, targets, **run_opts)
	results = scan.run(sync=sync, results=results)
	return results


def collect_results(result):
	"""Collect results from complex workflow by parsing all parents.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result object.

	Returns:
		list: List of collected results.
	"""
	out = []
	current = result
	while not result.ready():
		continue
	result = result.get()
	while(current.parent is not None):
		current = current.parent
		result = current.get()
		if isinstance(result, list):
			out.extend(result)
	return out


def get_table_fields(output_type):
	"""Get output fields and sort fields based on output type.

	Args:
		output_type (str): Output type.

	Returns:
		tuple: Tuple of sort_by (tuple), output_fields (list).
	"""
	# TODO: Rework this
	from secsy.tools.http import HTTPCommand
	from secsy.tools.recon import naabu, subfinder
	from secsy.tools.vuln import VulnCommand
	sort_by = ()
	output_fields = []
	output_map = {
		'vulnerability': VulnCommand,
		'port': naabu,
		'url': HTTPCommand,
		'subdomain': subfinder
	}
	if output_type in output_map:
		task_cls = output_map[output_type]
		sort_by = task_cls.output_table_sort_fields
		if not sort_by:
			sort_by = (task_cls.output_field,)
		output_fields = task_cls.output_table_fields
	return sort_by, output_fields


def merge_extracted_values(results, opts):
	"""Run extractors and merge extracted values with option dict.

	Args:
		results (list): List of results.
		opts (dict): Options.

	Returns:
		tuple: targets, options.
	"""
	extractors = {k: v for k, v in opts.items() if k.endswith('_')}
	targets = None
	for key, val in extractors.items():
		key = key.rstrip('_')
		values = extract_from_results(results, val)
		if key == 'targets':
			targets = deduplicate(values)
		else:
			opts[key] = deduplicate(values)
	return targets, opts


def extract_from_results(results, extractors):
	"""Extract sub extractors from list of results dict.

	Args:
		results (list): List of dict.
		extractors (list): List of extractors to extract from.

	Returns:
		list: List of extracted results (flat).
	"""
	extracted = []
	if not isinstance(extractors, list):
		extractors = [extractors]
	for extractor in extractors:
		extracted.extend(process_extractor(results, extractor))
	return extracted


def process_extractor(results, extractor, ctx={}):
	"""Process extractor.

	Args:
		results (list): List of results.
		extractor (dict / str): extractor definition.

	Returns:
		list: List of extracted results.
	"""
	if isinstance(extractor, dict):
		_type = extractor['type']
		_field = extractor.get('field')
		_condition = extractor.get('condition', 'True')
	else:
		_type, _field = tuple(extractor.split('.'))
		_condition = 'True'
	items = [
		item for item in results if item['_type'] == _type and eval(_condition)
	]
	if _field:
		_field = '{' + _field + '}' if not _field.startswith('{') else _field
		return [_field.format(**item) for item in items]
	else:
		return items


def get_task_ids(result, ids=[]):
	"""Get all Celery task ids recursively.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result object.
		ids (list): List of ids.
	"""
	if result is None:
		return

	if isinstance(result, GroupResult):
		get_task_ids(result.parent, ids=ids)

	elif isinstance(result, AsyncResult):
		if result.id not in ids:
			ids.append(result.id)

	# Browse children
	if result.children:
		for child in result.children:
			get_task_ids(child, ids=ids)

	# Browse parent
	get_task_ids(result.parent, ids=ids)


def get_task_info(task_id):
	res = AsyncResult(task_id)
	data = {}
	if res.args and len(res.args) > 1:
		task_name = res.args[1]
		data['celery_task_id'] = task_id
		data['name'] = task_name
		data['state'] = res.state
		data['error'] = ''
		data['track'] = False
		data['results'] = []
		data['count'] = 0
		if res.info and not isinstance(res.info, list): # only available in RUNNING, SUCCESS, FAILURE states
			if isinstance(res.info, BaseException):
				data['track'] = True
				data['error'] = str(res.info)
			else:
				data['track'] = res.info.get('track', False)
				data['results'] = res.info.get('results', [])
				data['count'] = res.info.get('count', 0)
	# import json
	# console.print_json(json.dumps(data))
	return data