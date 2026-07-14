import os
import re

from secator.config import CONFIG
from secator.output_types import Error
from secator.query.ast import substitute_ctx_constants
from secator.utils import deduplicate, debug


def resolve_task_queue(task_cls, opts):
	"""Resolve the Celery queue (== task profile) for a task at dispatch time.

	A dynamic (callable) profile encodes the task author's per-run resource routing (e.g. katana
	headless -> extra_large) and always wins. A static profile is overridable via
	``tasks.overrides.<task>.profile`` so an operator can route a task to a dedicated queue (e.g.
	nmap -> a long-running pool via SECATOR_TASKS_OVERRIDES_NMAP_PROFILE) without code changes —
	while never being able to silently flatten a dynamic profile onto a single queue and send a
	heavy variant to a small pool.

	Args:
		task_cls (type): The task class (a Command subclass).
		opts (dict): Run options, passed to a dynamic profile callable.

	Returns:
		str: The queue name.
	"""
	if callable(task_cls.profile):
		return task_cls.profile(opts)
	# CONFIG.tasks.overrides is a DotMap-like Config that auto-vivifies missing keys to a truthy
	# empty object (not None), so normalize to a plain dict before lookups.
	task_overrides = CONFIG.tasks.overrides.get(task_cls.__name__, {})
	if hasattr(task_overrides, 'toDict'):
		task_overrides = task_overrides.toDict()
	override = task_overrides.get('profile')
	return override if override else task_cls.profile


def _format_nested(template, data):
	"""Format a string template supporting nested dot notation like {extra_data.password}.

	Replaces {key} and {key.subkey} tokens by traversing nested dicts.
	Missing or non-traversable keys resolve to empty string.
	"""
	def replace_token(match):
		key = match.group(1)
		keys = key.split('.')
		value = data
		for k in keys:
			if isinstance(value, dict):
				value = value.get(k)
			else:
				value = None
			if value is None:
				break
		return str(value) if value is not None else ''
	return re.sub(r'\{([\w.]+)\}', replace_token, template)


def run_extractors(results, opts, inputs=None, ctx=None, dry_run=False):
	"""Run extractors and merge extracted values with option dict.

	Args:
		results (list): List of results.
		opts (dict): Options.
		inputs (list): Original inputs.
		ctx (dict): Context.
		dry_run (bool): Dry run.

	Returns:
		tuple: inputs, options, errors.
	"""
	if inputs is None:
		inputs = []
	if ctx is None:
		ctx = {}
	if 'parent_scope' not in ctx:
		ctx['parent_scope'] = opts.get('parent_scope')
	if 'node_chain_start' not in ctx:
		ctx['node_chain_start'] = opts.get('node_chain_start', False)
	parent_scope = ctx.get('parent_scope')
	extractors = {k: v for k, v in opts.items() if k.endswith('_')}
	if dry_run:
		input_extractors = {k: v for k, v in extractors.items() if k.rstrip('_') == 'targets'}
		opts_extractors = {k: v for k, v in extractors.items() if k.rstrip('_') != 'targets'}
		if input_extractors:
			dry_inputs = [" && ".join([fmt_extractor(v) for k, val in input_extractors.items() for v in val])]
		else:
			dry_inputs = inputs
		if opts_extractors:
			dry_opts = {k.rstrip('_'): [" && ".join([fmt_extractor(v) for v in val])] for k, val in opts_extractors.items()}
		else:
			dry_opts = {}
		inputs = dry_inputs
		opts.update(dry_opts)
		return inputs, opts, []

	errors = []
	computed_inputs = []
	input_extractors = False
	computed_opts = {}

	for key, val in extractors.items():
		key = key.rstrip('_')
		ctx['key'] = key
		values, err = extract_from_results(results, val, ctx=ctx)
		errors.extend(err)
		if key == 'targets':
			input_extractors = True
			targets = deduplicate(values)
			computed_inputs.extend(targets)
		else:
			computed_opt = deduplicate(values)
			if computed_opt:
				computed_opts[key] = computed_opt
				opts[key] = computed_opts[key]
	if input_extractors:
		debug('computed_inputs', obj=computed_inputs, sub='extractors')
		inputs = computed_inputs
	elif parent_scope and not opts.get('chunk'):
		# Scoped target fallback: query scope-tagged Targets via the same engine (backend
		# does the filtering) instead of scanning the full in-memory fan-in.
		scoped_targets = process_extractor(results, {'type': 'target', 'field': 'name'}, ctx=ctx)
		combined = deduplicate(scoped_targets)
		if combined:
			debug('using scope-tagged targets as inputs', obj=combined, sub='extractors')
			inputs = combined
	if computed_opts:
		debug('computed_opts', obj=computed_opts, sub='extractors')
	return inputs, opts, errors


def fmt_extractor(extractor):
	"""Format extractor.

	Args:
		extractor (dict / str): extractor definition.

	Returns:
		str: formatted extractor.
	"""
	parsed_extractor = parse_extractor(extractor)
	if not parsed_extractor:
		return '<DYNAMIC[INVALID_EXTRACTOR]>'
	_type, _field, _condition, _group_by = parsed_extractor
	s = f'{_type}.{_field}'
	if _condition:
		_condition = _condition.replace("'", '').replace('"', '')
		s = f'{s} if {_condition}'
	if _group_by:
		s = f'{s} group_by {_group_by}'
	return f'<DYNAMIC({s})>'


def extract_from_results(results, extractors, ctx=None):
	"""Extract sub extractors from list of results dict.

	Args:
		results (list): List of dict.
		extractors (list): List of extractors to extract from.
		ctx (dict, optional): Context.

	Returns:
		tuple: List of extracted results (flat), list of errors.
	"""
	if ctx is None:
		ctx = {}
	all_results = []
	errors = []
	key = ctx.get('key', 'unknown')
	ancestor_id = ctx.get('ancestor_id', None)
	if not isinstance(extractors, list):
		extractors = [extractors]
	for extractor in extractors:
		try:
			extractor_results = process_extractor(results, extractor, ctx=ctx)
			msg = f'extracted [bold]{len(extractor_results)}[/] / [bold]{len(results)}[/] for key [bold]{key}[/] with extractor [bold]{fmt_extractor(extractor)}[/]'  # noqa: E501
			if ancestor_id:
				msg = f'{msg} ([bold]ancestor_id[/]: {ancestor_id})'
			debug(msg, sub='extractors')
			all_results.extend(extractor_results)
		except Exception as e:
			error = Error.from_exception(e)
			errors.append(error)
	if key == 'targets':
		ctx['targets'] = all_results
	return all_results, errors


def parse_extractor(extractor):
	"""Parse extractor.

	Args:
		extractor (dict / str): extractor definition.

	Returns:
		tuple|None: type, field, condition, group_by or None if invalid.
	"""
	# Parse extractor, it can be a dict or a string (shortcut)
	if isinstance(extractor, dict):
		_type = extractor['type']
		_field = extractor.get('field')
		_condition = extractor.get('condition')
		_group_by = extractor.get('group_by')
	else:
		parts = tuple(extractor.split('.'))
		if len(parts) == 2:
			_type = parts[0]
			_field = parts[1]
			_condition = None
			_group_by = None
		else:
			return None
	return _type, _field, _condition, _group_by


class StreamView:
	"""Lazy, streaming view over a run-scoped store query — the read-model for a run's findings.

	Iterating streams the backend cursor in batches (never materializes all N); ``len()`` is an
	indexed count; ``bool()`` is a cheap count. Dicts are rehydrated to OutputType on the fly.

	ponytail: ``__contains__`` is an O(N) stream + ``==`` scan — fine for the small membership
	checks in the integration tests; the RAM-critical paths use ``__iter__``/``__len__`` which
	stay flat. Upgrade __contains__ to a keyed exists-query if a hot path ever needs it.
	"""
	def __init__(self, engine, query, batch_size=1000, limit=0):
		self._engine = engine
		self._query = query
		self._batch_size = batch_size
		self._limit = limit

	def __iter__(self):
		n = 0
		for batch in self._engine.iterate(self._query, self._batch_size):
			for item in load_output_types(batch):
				yield item
				n += 1
				if self._limit and n >= self._limit:
					return

	def __len__(self):
		n = self._engine.count(self._query)
		return min(n, self._limit) if self._limit else n

	def __bool__(self):
		return self._engine.count(self._query) > 0

	def __contains__(self, item):
		return any(x == item for x in self)


def load_output_types(docs):
	"""Rehydrate store query results (dicts) into OutputType objects.

	Items already OutputType instances pass through; dicts are mapped by their ``_type``
	to the matching class and loaded. Docs with an unknown/missing type are skipped.
	The uuid is taken from ``_uuid`` (json/sqlite) or ``_id`` (mongodb).

	Args:
		docs (list): Store query results (dicts and/or OutputType objects).

	Returns:
		list[OutputType]: Rehydrated output types.
	"""
	from secator.output_types import OUTPUT_TYPES
	by_name = {o.get_name(): o for o in OUTPUT_TYPES}
	out = []
	for doc in docs:
		if isinstance(doc, dict):
			klass = by_name.get(doc.get('_type'))
			if not klass:
				continue
			item = klass.load(doc)
			if not item._uuid:
				item._uuid = str(doc.get('_uuid') or doc.get('_id') or '')
			out.append(item)
		elif hasattr(doc, '_type') and hasattr(doc, 'toDict'):
			# Already an OutputType. Structural check (not isinstance) so a mid-suite
			# module reload — which changes the OutputType class identity — can't drop it.
			out.append(doc)
	return out


def run_scope_query(ctx):
	"""Bound a query to the current run via the top-most present ancestry id (scan > workflow >
	task). Each store driver mints its {type}_id at on_init (native format) and stamps it into
	context, so descendants inherit it and findings carry it — uniform across all drivers, local
	json included. Without it, store backends leak across runs in a shared workspace."""
	for level in ('scan', 'workflow', 'task'):
		rid = ctx.get(f'{level}_id')
		if rid:
			return {f'_context.{level}_id': str(rid)}
	return {}


def build_extractor_query(extractor, ctx):
	"""Translate an extractor (type + condition) into a Mongo-style query dict, or None when a
	constant gate makes it yield nothing."""
	from secator.query.utils import python_expr_to_mongo
	parsed = parse_extractor(extractor)
	if not parsed:
		return None
	_type, _field, _condition, _group_by = parsed
	query = {'_type': _type}
	residual = substitute_ctx_constants(_condition, ctx)
	if residual is None:
		return None
	if residual:
		# python_expr_to_mongo treats `item.` as neutral (no _type), so force the extractor's
		# declared type afterwards — it is authoritative over any prefix in the condition.
		query.update(python_expr_to_mongo(residual))
		query['_type'] = _type
	query.update(run_scope_query(ctx))
	# Additional narrowing the old per-item eval applied within the run.
	parent_scope = ctx.get('parent_scope')
	ancestor_id = ctx.get('ancestor_id')
	if _type == 'target' and parent_scope:
		query['_context.scope'] = parent_scope
	elif ancestor_id and not ctx.get('node_chain_start', False):
		query['_context.ancestor_id'] = str(ancestor_id)
	return query


def process_extractor(results, extractor, ctx=None):
	"""Process extractor.

	Args:
		results (list): List of results.
		extractor (dict / str): extractor definition.

	Returns:
		list: List of extracted results.
	"""
	if ctx is None:
		ctx = {}
	key = ctx.get('key')
	parsed_extractor = parse_extractor(extractor)
	if not parsed_extractor:
		return results
	_type, _field, _condition, _group_by = parsed_extractor

	query = build_extractor_query(extractor, ctx)
	if query is None:
		return []
	in_memory = ctx.get('results') or results
	if in_memory:
		# Caller handed us a materialized finding list (unit tests / sync library callers):
		# filter it directly with the same match_query the local backend uses — no store
		# round-trip. This is an explicit argument, NOT the runner's in-memory results.
		from secator.query.json import match_query
		results = [r for r in in_memory if match_query(r, query)]
	else:
		# Live run: findings live only in the store. Query it — the DB backend pushes the
		# filter down (fan-in never materialized, RC#6 OOM fix); the local backend reads the
		# run's report.json files.
		from secator.query import QueryEngine
		results = QueryEngine(ctx.get('workspace_id'), context={
			'drivers': ctx.get('drivers', []),
			'workspace_name': ctx.get('workspace_name'),
			'report_dir': ctx.get('report_dir'),
		}).search(query)
	debug(f'extracted {len(results)} results (key: {key}) via query {query}', sub='extractor')

	if _field:
		already_formatted = '{' in _field and '}' in _field
		_field = '{' + _field + '}' if not already_formatted else _field

		if _group_by:
			already_formatted_gb = '{' in _group_by and '}' in _group_by
			_group_by = '{' + _group_by + '}' if not already_formatted_gb else _group_by
			groups = {}
			for item in results:
				item_dict = _item_dict(item)
				group_key = _format_nested(_group_by, item_dict)
				value = _format_nested(_field, item_dict)
				if not group_key or not value:
					continue
				prefix = value.split('~')[0] if '~' in value else value
				if not prefix:
					continue
				bucket = groups.setdefault(group_key, [])
				if prefix not in bucket:
					bucket.append(prefix)
			results = [','.join(hosts) + '~' + group_key for group_key, hosts in groups.items()]
		else:
			results = [v for v in (_format_nested(_field, _item_dict(item)) for item in results) if v]
	return results


def _item_dict(item):
	"""Return an item as a dict, whether it's a raw finding dict (DB backend) or an
	OutputType object (local backend)."""
	return item if isinstance(item, dict) else item.toDict()


def get_task_folder_id(path):
	names = []
	if not os.path.exists(path):
		return 0
	for f in os.scandir(path):
		if f.is_dir():
			try:
				int(f.name)
				names.append(int(f.name))
			except ValueError:
				continue
	names.sort()
	if names:
		return names[-1] + 1
	return 0
