import operator

from secator.config import CONFIG
from secator.output_types import FINDING_TYPES, OutputType
from secator.utils import get_file_timestamp, traceback_as_string
from secator.rich import console
from secator.runners._helpers import extract_from_results

import concurrent.futures
from threading import Lock


def remove_duplicates(objects):
	unique_objects = []
	lock = Lock()

	def add_if_unique(obj):
		nonlocal unique_objects  # noqa: F824
		with lock:
			# Perform linear search to check for duplicates
			if all(obj != existing_obj for existing_obj in unique_objects):
				unique_objects.append(obj)

	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		# Execute the function concurrently for each object
		executor.map(add_if_unique, objects)

	return unique_objects


# TODO: initialize from data, not from runner
class Report:
	"""Report class.

	Args:
		runner (secator.runners.Runner): Runner instance.
		title (str): Report title.
		exporters (list): List of exporter classes.
	"""
	def __init__(self, runner, title=None, exporters=[]):
		self.title = title or f'{runner.config.type}_{runner.config.name}'
		self.runner = runner
		self.timestamp = get_file_timestamp()
		self.exporters = exporters
		self.workspace_name = runner.workspace_name
		self.output_folder = runner.reports_folder

	def send(self):
		for report_cls in self.exporters:
			try:
				report_cls(self).send()
			except Exception as e:
				console.print(
					f'[bold red]Could not create exporter {report_cls.__name__} for {self.__class__.__name__}: '
					f'{str(e)}[/]\n[dim]{traceback_as_string(e)}[/]',
				)

	def build(self, extractors=[], dedupe=CONFIG.runners.remove_duplicates):
		# Prepare report structure
		runner_fields = {
			'name',
			'status',
			'targets',
			'start_time',
			'end_time',
			'elapsed',
			'elapsed_human',
			'run_opts',
			'results_count'
		}
		data = {
			'info': {k: v for k, v in self.runner.toDict().items() if k in runner_fields},
			'results': {}
		}
		if 'results' in data['info']:
			del data['info']['results']
		data['info']['title'] = self.title
		data['info']['errors'] = self.runner.errors

		# Fill report
		for output_type in FINDING_TYPES:
			output_name = output_type.get_name()
			sort_by, _ = get_table_fields(output_type)
			items = [
				item for item in self.runner.results
				if isinstance(item, OutputType) and item._type == output_name
			]
			if items:
				if sort_by and all(sort_by):
					try:
						items = sorted(items, key=operator.attrgetter(*sort_by))
					except TypeError as e:
						console.print(f'[bold red]Could not sort {output_name} by {sort_by}: {str(e)}[/]')
						console.print(f'[dim]{traceback_as_string(e)}[/]')
				if dedupe:
					items = remove_duplicates(items)
				if extractors:
					all_res = []
					extractors_type = [extractor for extractor in extractors if extractor.get('type') == output_name]
					for extractor in extractors_type:
						op = extractor.get('op', 'or')
						res, errors = extract_from_results(items, extractors=[extractor])
						# console.print(f'{extractor} --> {len(res)} results')
						if not res:
							continue
						if errors:
							data['info']['errors'] = errors
						if res:
							if op == 'or':
								all_res = all_res + res
							else:
								if not all_res:
									all_res = res
								else:
									all_res = [item for item in res if item in all_res]
					items = remove_duplicates(all_res) if dedupe else all_res
				data['results'][output_name] = items

		# Save data
		self.data = data

	def is_empty(self):
		return all(not items for items in self.data['results'].values())


def get_table_fields(output_type):
	"""Get output fields and sort fields based on output type.

	Args:
		output_type (str): Output type.

	Returns:
		tuple: Tuple of sort_by (tuple), output_fields (list).
	"""
	sort_by = ()
	output_fields = []
	if output_type in FINDING_TYPES:
		sort_by = output_type._sort_by
		output_fields = output_type._table_fields
	return sort_by, output_fields
