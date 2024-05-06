import operator

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES, OutputType
from secator.utils import merge_opts, get_file_timestamp
from secator.rich import console


# TODO: initialize from data, not from runner
class Report:
	"""Report class.

	Args:
		runner (secator.runners.Runner): Runner instance.
		title (str): Report title.
		exporters (list): List of exporter classes.
	"""
	def __init__(self, runner, title=None, exporters=[]):
		self.title = title or f'{runner.__class__.__name__.lower()}_{runner.config.name}'
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
					f'Could not create exporter {report_cls.__name__} for {self.__class__.__name__}: {str(e)}',
					style='bold red')

	def build(self):
		# Trim options
		from secator.decorators import DEFAULT_CLI_OPTIONS
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
			if output_type.__name__ == 'Progress':
				continue
			output_name = output_type.get_name()
			sort_by, _ = get_table_fields(output_type)
			items = [
				item for item in self.runner.results
				if isinstance(item, OutputType) and item._type == output_name
			]
			if CONFIG.runners.remove_duplicates:
				items = [item for item in items if not item._duplicate]
			if items:
				if sort_by and all(sort_by):
					items = sorted(items, key=operator.attrgetter(*sort_by))
				data['results'][output_name] = items

		# Save data
		self.data = data


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
