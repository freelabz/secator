import ast
import operator
import os
import re

from secator.config import CONFIG
from secator.output_types import Error
from secator.utils import deduplicate, debug


_COMPARE_OPS = {
	ast.Eq: operator.eq,
	ast.NotEq: operator.ne,
	ast.Lt: operator.lt,
	ast.LtE: operator.le,
	ast.Gt: operator.gt,
	ast.GtE: operator.ge,
	ast.In: lambda a, b: a in b,
	ast.NotIn: lambda a, b: a not in b,
}


def _opts_get(opts, name):
	"""Read an opt value from a dict or DotMap, returning None when absent."""
	if hasattr(opts, 'get'):
		return opts.get(name)
	return getattr(opts, name, None)


def _fold_ctx(node, opts, targets):
	"""Fold ctx-constants (opts.*/targets/len(targets)) in an AST node.

	Returns (is_const, value_or_node): if is_const, value is a concrete Python value;
	otherwise value is an AST node with any constant children substituted in place.
	"""
	# Substitute `targets` -> list literal.
	if isinstance(node, ast.Name):
		if node.id == 'targets':
			return True, list(targets)
		return False, node

	# Substitute `opts.<name>` -> its runtime value; leave other attribute access
	# (finding fields like `url.verified`) as an AST node.
	if isinstance(node, ast.Attribute):
		if isinstance(node.value, ast.Name) and node.value.id == 'opts':
			return True, _opts_get(opts, node.attr)
		return False, node

	if isinstance(node, ast.Constant):
		return True, node.value

	# `len(targets)` (or len of any constant) folds to an int.
	if isinstance(node, ast.Call):
		if isinstance(node.func, ast.Name) and node.func.id == 'len' and len(node.args) == 1:
			is_const, val = _fold_ctx(node.args[0], opts, targets)
			if is_const:
				return True, len(val)
		return False, node

	if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
		is_const, val = _fold_ctx(node.operand, opts, targets)
		if is_const:
			return True, (not val)
		return False, ast.UnaryOp(op=ast.Not(), operand=val)

	if isinstance(node, ast.BoolOp):
		folded = [_fold_ctx(v, opts, targets) for v in node.values]
		is_and = isinstance(node.op, ast.And)
		kept = []
		for is_const, val in folded:
			if is_const:
				truthy = bool(val)
				if is_and and not truthy:
					return True, False       # short-circuit: AND with a falsy constant
				if not is_and and truthy:
					return True, True        # short-circuit: OR with a truthy constant
				continue                     # drop AND-true / OR-false constant operands
			kept.append(val)
		if not kept:
			return True, is_and              # all operands dropped: AND->True, OR->False
		if len(kept) == 1:
			return False, kept[0]
		return False, ast.BoolOp(op=node.op, values=kept)

	if isinstance(node, ast.Compare):
		left = _fold_ctx(node.left, opts, targets)
		comps = [_fold_ctx(c, opts, targets) for c in node.comparators]
		if left[0] and all(c[0] for c in comps) and len(node.ops) == 1:
			op = _COMPARE_OPS.get(type(node.ops[0]))
			if op is not None:
				return True, bool(op(left[1], comps[0][1]))
		rebuilt = ast.Compare(
			left=_as_node(left),
			ops=node.ops,
			comparators=[_as_node(c) for c in comps],
		)
		return False, rebuilt

	return False, node


def _as_node(folded):
	"""Turn a (is_const, value_or_node) pair back into an AST node for unparsing."""
	is_const, val = folded
	return ast.Constant(value=val) if is_const else val


def substitute_ctx_constants(condition, ctx):
	"""Fold opts.*/targets/len(targets) runtime constants out of an extractor condition.

	Returns the residual finding-field condition (a possibly-empty string) after constant
	folding, or None when a constant-only gate makes the whole condition falsy (the
	extractor must then yield nothing). An empty string means the condition folded to a
	constant-true gate (match everything of the extractor's type).
	"""
	if not condition or not str(condition).strip():
		return ''
	tree = ast.parse(str(condition).strip(), mode='eval').body
	is_const, node = _fold_ctx(tree, ctx.get('opts', {}) or {}, list(ctx.get('targets', []) or []))
	if is_const:
		return None if not bool(node) else ''
	return ast.unparse(node)


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


def build_extractor_query(extractor, ctx):
	"""Translate an extractor (type + condition) into a Mongo-style query dict.

	Folds opts/targets ctx-constants, rewrites the per-item Python condition to a query,
	and appends the same scope/ancestor filters the old per-item eval applied. Returns
	None when the extractor must yield nothing (a constant gate is falsy).
	"""
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
		# The condition references the item under `item.` or the type name; normalize the
		# `item.` alias to the type prefix so the translator emits the matching _type.
		expr = re.sub(r'\bitem\.', f'{_type}.', residual)
		query.update(python_expr_to_mongo(expr))
	# Mirror process_extractor's scope/ancestor scoping.
	parent_scope = ctx.get('parent_scope')
	ancestor_id = ctx.get('ancestor_id')
	node_chain_start = ctx.get('node_chain_start', False)
	if _type == 'target' and parent_scope:
		query['_context.scope'] = parent_scope
	elif ancestor_id and not node_chain_start:
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
	ancestor_id = ctx.get('ancestor_id')
	key = ctx.get('key')

	# Parse extractor, it can be a dict or a string (shortcut)
	parsed_extractor = parse_extractor(extractor)
	if not parsed_extractor:
		return results
	_type, _field, _condition, _group_by = parsed_extractor

	# Translate the extractor into a query and let the backend do the filtering. Under a
	# DB backend (mongodb/api/sqlite) this queries the store directly — the full fan-in is
	# never materialized on the heap (RC#6 OOM fix). Under the local backend it filters the
	# in-memory ctx['results'] (falling back to the passed-in results), mirroring the old
	# per-item eval byte-for-byte.
	query = build_extractor_query(extractor, ctx)
	if query is None:
		return []
	from secator.query import QueryEngine
	engine = QueryEngine(ctx.get('workspace_id'), context={
		'drivers': ctx.get('drivers', []),
		'results': ctx.get('results', results),
		'workspace_name': ctx.get('workspace_name'),
	})
	results = engine.search(query)

	debug(
		f'extracted {len(results)} results ([bold]ancestor_id[/]: {ancestor_id}, [bold]key[/]: {key}) '
		f'via query {query}', sub='extractor')

	# Format field if needed
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
