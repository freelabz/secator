from secator.config import CONFIG
from secator.output_types import FINDING_TYPES
from secator.utils import get_file_timestamp, traceback_as_string
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
					f'[bold red]Could not create exporter {report_cls.__name__} for {self.__class__.__name__}: {str(e)}[/]\n[dim]{traceback_as_string(e)}[/]',  # noqa: E501
				)

	def build(self, query=None, dedupe=CONFIG.runners.remove_duplicates):
		"""Build report data structure using QueryEngine for filtering and dedup.

		Args:
			query (dict): MongoDB-style filter query (e.g. {'_type': 'vulnerability'}).
			dedupe (bool): Whether to remove duplicate results.
		"""
		if query is None:
			query = {}
		from secator.query import QueryEngine

		runner_fields = {
			'name',
			'status',
			'targets',
			'start_time',
			'end_time',
			'elapsed',
			'elapsed_human',
			'run_opts',
			'results_count',
			'context',
		}
		data = {'info': {k: v for k, v in self.runner.toDict().items() if k in runner_fields}, 'results': {}}
		if 'results' in data['info']:
			del data['info']['results']
		data['info']['title'] = self.title
		data['info']['errors'] = getattr(self.runner, 'errors', [])

		# Build context for QueryEngine.
		# Pass runner.results directly (OutputType objects or dicts) to avoid
		# costly serialization. An absent 'results' key tells JsonBackend to
		# scan the filesystem instead.
		context = dict(getattr(self.runner, 'context', {}) or {})
		if 'results' not in context or not context.get('results'):
			raw_results = getattr(self.runner, 'results', []) or []
			if raw_results:
				context['results'] = raw_results
			elif 'results' in context:
				# Remove empty list so JsonBackend falls through to filesystem scan
				del context['results']
		if 'workspace_name' not in context:
			context['workspace_name'] = self.workspace_name

		engine = QueryEngine(self.workspace_name, context=context)
		results = engine.search(query, dedupe=dedupe)

		for output_type in FINDING_TYPES:
			output_name = output_type.get_name()
			data['results'][output_name] = [r for r in results if (r.get('_type') if isinstance(r, dict) else getattr(r, '_type', None)) == output_name]  # noqa: E501

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
