
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

from secsy.definitions import OUTPUT_TYPES, REPORTS_FOLDER
from secsy.rich import build_table, console
from secsy.runners._helpers import (get_task_ids, get_task_info,
									get_task_nodes, process_extractor)
from secsy.utils import get_file_timestamp, merge_opts, pluralize


class Runner:

	_print_table = True
	_save_html = True
	_save_json = True

	def __init__(self, config, targets, results=[], **run_opts):
		self.config = config
		self.run_opts = run_opts
		self.done = False
		self.results = results
		if not isinstance(targets, list):
			targets = [targets]
		self.targets = targets
		self.start_time = datetime.fromtimestamp(time())

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
				if item['_type'] in keep_fields
			])
		else:
			results = self.results
		return results

	def log_results(self):
		"""Log results.

		Args:
			results (list): List of results.
			output_types (list): List of result types to add to report.
		"""
		if not self.results or not self._print_table:
			return

		self.end_time = datetime.fromtimestamp(time())
		self.elapsed = self.end_time - self.start_time
		self.elapsed_human = humanize.naturaldelta(self.elapsed)

		# Print table
		title = f'{self.__class__.__name__} "{self.config.name}" results'
		render = Console(record=True)
		if self._print_table or self.run_opts.get('table', False):
			self.print_results_table(title, render)

		# Make HTML report
		if self._save_html or self.run_opts.get('html', False):
			timestr = get_file_timestamp()
			html_title = title.replace(' ', '_').replace("\"", '').lower()
			os.makedirs(REPORTS_FOLDER, exist_ok=True)
			html_path = f'{REPORTS_FOLDER}/{html_title}_{timestr}.html'
			render.save_html(html_path)
			console.print(f':file_cabinet: Saved HTML report to {html_path}')

		# Make JSON report
		if self._save_json:
			self.save_results_json(title)

		# Log execution results
		console.print(f':tada: [bold green]{self.__class__.__name__.capitalize()}[/] [bold magenta]{self.config.name}[/] [bold green]finished successfully in[/] [bold gold3]{self.elapsed_human}[/].')
		console.print()

	def print_results_table(self, title, render):
		render.print()
		h1 = Markdown(f'# {title}')
		render.print(h1, style='bold magenta', width=50)
		render.print()
		tables = []
		for output_type in OUTPUT_TYPES:
			sort_by, output_fields = get_table_fields(output_type)
			items = [item for item in self.results if item['_type'] == output_type]
			if items:
				_table = build_table(items, output_fields, sort_by)
				tables.append(tables)
				_type = pluralize(items[0]['_type'])
				render.print(_type.upper(), style='bold gold3', justify='left')
				render.print(_table)
				render.print()
		return tables

	def save_results_json(self, title):
		from secsy.decorators import DEFAULT_CLI_OPTIONS
		timestr = get_file_timestamp()
		json_title = title.replace(' ', '_').replace("\"", '').lower()
		json_path = f'{REPORTS_FOLDER}/{json_title}_{timestr}.json'

		# Trim options
		opts = merge_opts(self.config.options, self.run_opts)
		opts = {
			k: v for k, v in opts.items()
			if k not in DEFAULT_CLI_OPTIONS.keys() \
				and not k.startswith('print_') \
				and v is not None
		}

		# Prepare JSON report
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

		# Fill JSON report
		for output_type in OUTPUT_TYPES:
			sort_by, _ = get_table_fields(output_type)
			items = [item for item in self.results if item['_type'] == output_type]
			if items:
				if sort_by and all(sort_by):
					items = sorted(items, key=operator.itemgetter(*sort_by))
				data['results'][output_type] = items

		# Save JSON report to file
		with open(json_path, 'w') as f:
			json.dump(data, f, indent=2)
			console.print(f':file_cabinet: Saved JSON report to {json_path}')

	def process_live_tasks(self, result):
		tasks_progress = Progress(
			SpinnerColumn('dots'),
			TextColumn('[bold gold3]{task.fields[name]}[/]'),
			TextColumn('[dim gold3]{task.fields[chunk_info]}[/]'),
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
			res = AsyncResult(result.id)
			while True:
				task_ids = []
				get_task_ids(result, ids=task_ids)
				for task_id in task_ids:
					info = get_task_info(task_id)
					if not info or info.get('chunk'):
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

				# Update all tasks to 100 %
				if res.ready():
					for progress_id in tasks_progress.values():
						progress.update(progress_id, advance=100)
					break

				# Sleep between updates
				sleep(1)

		# Get task tree
		nodes = []
		ids = []
		get_task_nodes(result, ids=ids, nodes=nodes, parent=None)
		nodes = sorted(nodes, key=lambda x: x['level'])
		nodes = build_nodes_hierarchy(nodes)

		if errors:
			console.print()
			console.log('Errors:', style='bold red')
			for error in errors:
				console.print('  ' + error)


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