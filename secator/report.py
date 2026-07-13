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

	def build(self, query=None, dedupe=CONFIG.runners.remove_duplicates, limit=0, stream=False):
		"""Build report data structure using QueryEngine for filtering and dedup.

		Args:
			query (dict): MongoDB-style filter query (e.g. {'_type': 'vulnerability'}).
			dedupe (bool): Whether to remove duplicate results.
			limit (int): Maximum number of results to return (0 = no limit).
			stream (bool): When True, data['results'][type] is a lazy per-type StreamView (the
				live-run export path — peak stays flat). When False (report_show/library display),
				materialize per-type lists (subscriptable, dedup in-memory) — the current behavior.
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
		data['info']['warnings'] = getattr(self.runner, 'warnings', [])

		# Build context for QueryEngine.
		# Query the store for this run's findings. With the inter-task result payload
		# dropped, a live run's findings live only in the store (the live report.json files
		# locally, or the DB), which the backend reads directly. runner.results is still
		# passed as an in-memory FALLBACK for callers that have no live files (report_show,
		# library Report(runner)); JsonBackend prefers the live files when present (#1299),
		# so for a real run this fallback never shadows the store.
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

		# Bound the query to THIS run so a shared workspace's other runs don't leak in.
		from secator.runners._helpers import run_scope_query, StreamView
		scope = run_scope_query(context)
		if scope:
			query = {'$and': [query, scope]} if (query and set(query) & set(scope)) else {**query, **scope}

		workspace_id = context.get('workspace_id')
		engine = QueryEngine(workspace_id, context=context)
		from secator.output_types.target import Target

		if stream:
			# Live-run path: per-type STREAMING views — nothing materialized here; each exporter
			# iterates its type's cursor, so peak stays flat through report generation. Dedup is
			# store-side (tag_duplicates flags duplicates), excluded by query.
			if dedupe:
				dup = {'_context.workspace_duplicate': {'$ne': True}}
				query = {'$and': [query, dup]} if (query and set(query) & set(dup)) else {**query, **dup}
			for output_type in list(FINDING_TYPES) + [Target]:
				name = output_type.get_name()
				type_q = {'$and': [query, {'_type': name}]} if '_type' in query else {**query, '_type': name}
				data['results'][name] = StreamView(engine, type_q, limit=limit)
			self.data = data
			return

		# Display path (report_show / library): materialize per-type lists (subscriptable, in-memory dedup).
		results = engine.search(query, limit=limit, dedupe=dedupe)
		for output_type in list(FINDING_TYPES) + [Target]:
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
