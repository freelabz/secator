import csv
import json
import operator
import os
from datetime import datetime
from time import sleep, time

import humanize
from celery.result import AsyncResult
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import (Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)

from secsy.definitions import DEBUG, REPORTS_FOLDER, GOOGLE_DRIVE_PARENT_FOLDER_ID, GOOGLE_CREDENTIALS_PATH
from secsy.rich import build_table, console
from secsy.output_types import OUTPUT_TYPES
from secsy.runners._helpers import (get_task_ids, get_task_info,
                                    process_extractor)
from secsy.utils import get_file_timestamp, merge_opts, pluralize


class Runner:

	_print_table = True
	_save_html = True
	_save_json = True
	_save_csv = True
	_save_google_sheet = True


	def __init__(self, config, targets, results=[], **run_opts):
		self.config = config
		self.run_opts = run_opts
		self.done = False
		self.results = results
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.start_time = datetime.fromtimestamp(time())
		self.errors = []


	def log_start(self):
		"""Log runner start."""
		remote_str = 'starting' if self.sync else 'sent to [bold gold3]Celery[/] worker'
		runner_name = self.__class__.__name__
		console.print(f':tada: [bold green]{runner_name}[/] [bold magenta]{self.config.name}[/] [bold green]{remote_str}...[/]')
		self.log_header()


	def log_header(self):
		runner_name = self.__class__.__name__
		opts = merge_opts(self.run_opts, self.config.options)
		console.print()
		console.print(f'[bold gold3]{runner_name}:[/]    {self.config.name}')

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
		from secsy.decorators import DEFAULT_CLI_OPTIONS
		items = [
			f'[italic]{k}[/]: {v}'
			for k, v in opts.items()
			if not k.startswith('print_') \
				and k not in DEFAULT_CLI_OPTIONS \
				and v is not None
		]
		if items:
			console.print('Options:', style='bold gold3')
			for item in items:
				console.print(f' • {item}')

		console.print()


	def log_results(self):
		"""Log results.

		Args:
			results (list): List of results.
			output_types (list): List of result types to add to report.
		"""
		for error in self.errors:
			console.log(error, style='bold red')

		if not self.done or not self._print_table:
			return

		if not self.results:
			console.log('No results found.', style='bold red')
			return

		self.end_time = datetime.fromtimestamp(time())
		self.elapsed = self.end_time - self.start_time
		self.elapsed_human = humanize.naturaldelta(self.elapsed)

		# Print table
		title = f'{self.__class__.__name__} "{self.config.name}" results'
		render = Console(record=True)
		timestr = get_file_timestamp()
		if self._print_table or self.run_opts.get('table', False):
			Runner.print_results_table(self.results, title, render=console)

		# Make HTML report
		if self._save_html or self.run_opts.get('html', False):
			html_title = title.replace(' ', '_').replace("\"", '').lower()
			os.makedirs(REPORTS_FOLDER, exist_ok=True)
			html_path = f'{REPORTS_FOLDER}/{html_title}_{timestr}.html'
			render.save_html(html_path)
			console.print(f':file_cabinet: Saved HTML report to {html_path}')

		# Make JSON report
		if self._save_json:
			self.save_results_json(title, timestr)

		# Make CSV report
		if self._save_csv:
			self.save_results_csv(title, timestr)

		# Make Google Sheet report
		if self._save_google_sheet:
			self.save_results_google_sheets(title, timestr)

		# Log execution results
		console.print(f':tada: [bold green]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.config.name}[/] [bold green]finished successfully in[/] [bold gold3]{self.elapsed_human}[/].')
		console.print()


	@staticmethod
	def get_live_results(result):
		"""Poll Celery subtasks results in real-time. Fetch task metadata and 
		partial results from each task that runs.

		Args:
			result (celery.result.AsyncResult): Result object.

		Yields:
			dict: Current task state and results.
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

			# Update all tasks to 100 %
			if res.ready():
				break

			# Sleep between updates
			sleep(1)


	def process_live_tasks(self, result):
		tasks_progress = Progress(
			SpinnerColumn('dots'),
			TextColumn('[bold gold3]{task.fields[name]}[/]'),
			TextColumn('[dim gold3]{task.fields[chunk_info]}[/]'),
			TextColumn('{task.fields[state]:<20}'),
			TimeElapsedColumn(),
			TextColumn('{task.fields[count]}'),
			TextColumn('\[[bold magenta]{task.fields[id]:<30}[/]]'),
			refresh_per_second=1
		)
		state_colors = {
			'RUNNING': 'bold yellow',
			'SUCCESS': 'bold green',
			'FAILURE': 'bold red',
			'REVOKED': 'bold magenta'
		}
		with tasks_progress as progress:

			# Make progress tasks
			tasks_progress = {}

			# Get live results and print progress
			for info in Runner.get_live_results(result):

				# Re-yield so that we can consume it externally
				yield info

 				# Ignore partials in output unless DEBUG=1
				if info['chunk'] and not DEBUG:
					continue

				# Handle error if any
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
		"""Filter results."""
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


	@staticmethod
	def print_results_table(results, title, render=console, exclude_fields=[]):
		render.print()
		h1 = Markdown(f'# {title}')
		render.print(h1, style='bold magenta', width=50)
		render.print()
		tables = []
		for output_type in OUTPUT_TYPES:
			sort_by, output_fields = output_type._sort_by, output_type._table_fields
			items = [item for item in results if item._type == output_type.get_name()]
			if items:
				_table = build_table(
					items,
					output_fields=output_fields,
					exclude_fields=exclude_fields,
					sort_by=sort_by)
				tables.append(_table)
				_type = pluralize(items[0]._type)
				render.print(_type.upper(), style='bold gold3', justify='left')
				render.print(_table)
				render.print()
		return tables


	def prepare_report(self, title):
		from secsy.decorators import DEFAULT_CLI_OPTIONS
		json_title = title.replace(' ', '_').replace("\"", '').lower()

		# Trim options
		opts = merge_opts(self.config.options, self.run_opts)
		opts = {
			k: v for k, v in opts.items()
			if k not in DEFAULT_CLI_OPTIONS \
				and not k.startswith('print_') \
				and v is not None
		}

		# Prepare report structure
		data = {
			'info': {
				'title': json_title,
				'type': self.__class__.__name__,
				'name': self.config.name,
				'targets': self.targets,
				'total_time': str(self.elapsed),
				'total_human': self.elapsed_human,
				'opts': opts,
			},
			'results': {},
		}

		# Fill report
		for output_type in OUTPUT_TYPES:
			sort_by, _ = get_table_fields(output_type)
			items = [item for item in self.results if item._type == output_type]
			if items:
				if sort_by and all(sort_by):
					items = sorted(items, key=operator.itemgetter(*sort_by))
				data['results'][output_type] = items
		return data


	def save_results_csv(self, title, timestr):
		data = self.prepare_report(title)
		title = data['info']['title']
		results = data['results']
		csv_paths = []
		for output_type, items in results.items():
			if not items:
				continue
			if output_type == 'target':
				continue
			keys = list(items[0].keys())
			csv_path = f'{REPORTS_FOLDER}/{title}_{output_type}_{timestr}.csv'
			csv_paths.append(csv_path)
			with open(csv_path, 'w', newline='') as output_file:
				dict_writer = csv.DictWriter(output_file, keys)
				dict_writer.writeheader()
				dict_writer.writerows(items)
		if len(csv_paths) == 1:
			csv_paths_str = csv_paths[0]
		else:
			csv_paths_str = '\n   • ' + '\n   • '.join(csv_paths)
		console.print(f':file_cabinet: Saved CSV reports to {csv_paths_str}')


	def save_results_google_sheets(self, title, timestr):
		import gspread
		import yaml
		data = self.prepare_report(title)
		info = data['info']
		title = data['info']['title']
		sheet_title = f'{data["info"]["title"]}_{timestr}'
		results = data['results']
		if not GOOGLE_CREDENTIALS_PATH:
			console.print(':file_cabinet: Missing GOOGLE_CREDENTIALS_PATH to save to Google Sheets', style='red')
			return
		if not GOOGLE_DRIVE_PARENT_FOLDER_ID:
			console.print(':file_cabinet: Missing GOOGLE_DRIVE_PARENT_FOLDER_ID to save to Google Sheets.', style='red')
			return
		client = gspread.service_account(GOOGLE_CREDENTIALS_PATH)
		sheet = client.create(title, folder_id=GOOGLE_DRIVE_PARENT_FOLDER_ID)

		# Add options worksheet for input data
		info = data['info']
		info['targets'] = '\n'.join(info['targets'])
		info['opts'] = yaml.dump(info['opts'])
		keys = [k.replace('_', ' ').upper() for k in list(info.keys())]
		ws = sheet.add_worksheet('OPTIONS', rows=2, cols=len(keys))
		sheet.values_update(
			ws.title,
			params={'valueInputOption': 'USER_ENTERED'},
			body={'values': [keys, list(info.values())]}
		)

		# Add one worksheet per output type
		for output_type, items in results.items():
			if not items:
				continue
			keys = [
				k.replace('_', ' ').upper()
				for k in list(items[0].keys())
			]
			csv_path = f'{REPORTS_FOLDER}/{title}_{output_type}_{timestr}.csv'
			sheet_title = pluralize(output_type).upper()
			ws = sheet.add_worksheet(sheet_title, rows=len(items), cols=len(keys))
			with open(csv_path, 'r') as f:
				data = csv.reader(f)
				data = list(data)
				data[0] = [
					k.replace('_', ' ').upper()
					for k in data[0]
				]
				sheet.values_update(
					ws.title,
					params={'valueInputOption': 'USER_ENTERED'},
					body={'values': data}
				)

		# Delete 'default' worksheet
		ws = sheet.get_worksheet(0)
		sheet.del_worksheet(ws)

		console.print(f':file_cabinet: Saved Google Sheets reports to [u magenta]{sheet.url}[/]')


	def save_results_json(self, title, timestr):
		data = self.prepare_report(title)
		title = data['info']['title']
		json_path = f'{REPORTS_FOLDER}/{title}_{timestr}.json'

		# Save JSON report to file
		with open(json_path, 'w') as f:
			json.dump(data, f, indent=2)
			console.print(f':file_cabinet: Saved JSON report to {json_path}')


# TODO: move all functions to utils

def plusplus(oldChar):
     return chr(ord(oldChar)+1)

def build_nodes_hierarchy(nodes):
	for node in nodes:
		parent_id = node.get('parent')
		parent = [n for n in nodes if n['celery_id'] == parent_id]
		if parent:
			parent = parent[0]
			children = parent.get('children', [])
			children.append(node['celery_id'])
			parent['children'] = children
	return nodes


def build_tree(root, node, nodes):
	name = node.get('name')

	# Skip utility Celery tasks
	while name is None:
		children = [c for c in nodes if c['celery_id'] in node.get('children', [])]
		if not children:
			break
		node = children[0]
		name = node.get('name')

	# Make subtree, skip _group subtree
	if name == '_group':
		subtree = root
	else:
		subtree = root.add(name)

	# Add children to subtree
	children = [
		c for c in nodes
		if c['celery_id'] in node.get('children', [])
	]
	for child in children:
		build_tree(subtree, child, nodes)


def get_table_fields(output_type):
	"""Get output fields and sort fields based on output type.

	Args:
		output_type (str): Output type.

	Returns:
		tuple: Tuple of sort_by (tuple), output_fields (list).
	"""
	# TODO: Rework this with new output models
	from secsy.tasks._categories import HTTPCommand, VulnCommand
	from secsy.tasks.naabu import naabu
	from secsy.tasks.subfinder import subfinder
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