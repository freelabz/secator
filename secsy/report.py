import operator
import os
from pathlib import Path

from secsy.definitions import REPORTS_FOLDER
from secsy.output_types import OUTPUT_TYPES, OutputType
from secsy.utils import merge_opts, pluralize, get_file_timestamp, print_results_table


# TODO: initialize from data, not from runner
class Report:
	"""Report class.

	Args:
		runner (secsy.runners.Runner): Runner instance.
		title (str): Report title.
		exporters (list): List of exporter classes.
	"""
	def __init__(self, runner, title=None, exporters=[]):
		self.title = title or f'{runner.__class__.__name__.lower()}_{runner.config.name}'
		self.runner = runner
		self.timestamp = get_file_timestamp()
		self.exporters = exporters
		self.workspace_name = runner.workspace_name
		self.create_local_folders()

	def as_table(self):
		print_results_table(self.results, self.title)

	def send(self):
		for report_cls in self.exporters:
			report_cls(self).send()

	def build(self):
		# Trim options
		from secsy.decorators import DEFAULT_CLI_OPTIONS
		opts = merge_opts(self.runner.config.options, self.runner.run_opts)
		opts = {
			k: v for k, v in opts.items()
			if k not in DEFAULT_CLI_OPTIONS
			and not k.startswith('print_')
			and v is not None
		}

		# Prepare report structure
		data = {
			'info': {
				'title': self.title,
				'runner': self.runner.__class__.__name__,
				'name': self.runner.config.name,
				'targets': self.runner.targets,
				'total_time': str(self.runner.elapsed),
				'total_human': self.runner.elapsed_human,
				'opts': opts,
			},
			'results': {},
		}

		# Fill report
		for output_type in OUTPUT_TYPES:
			output_name = output_type.get_name()
			sort_by, _ = get_table_fields(output_type)
			items = [item for item in self.runner.results if isinstance(item, OutputType) and item._type == output_name]
			if items:
				if sort_by and all(sort_by):
					items = sorted(items, key=operator.attrgetter(*sort_by))
				data['results'][output_name] = items

		# Save data
		self.data = data

	def create_local_folders(self):
		output_folder = Path(REPORTS_FOLDER)
		if self.runner.workspace_name:
			output_folder = output_folder / Path(self.runner.workspace_name)
		output_folder = output_folder / Path(pluralize(self.runner.__class__.__name__).lower())
		output_folder = str(output_folder)
		os.makedirs(output_folder, exist_ok=True)
		self.output_folder = output_folder


def get_table_fields(output_type):
	"""Get output fields and sort fields based on output type.

	Args:
		output_type (str): Output type.

	Returns:
		tuple: Tuple of sort_by (tuple), output_fields (list).
	"""
	sort_by = ()
	output_fields = []
	if output_type in OUTPUT_TYPES:
		sort_by = output_type._sort_by
		output_fields = output_type._table_fields
	return sort_by, output_fields
