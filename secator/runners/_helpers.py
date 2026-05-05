import os
import re

from dotmap import DotMap
from secator.output_types import Error
from secator.utils import deduplicate, debug


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
		scoped_targets = [
			item.name for item in results
			if item._type == 'target' and item._context.get('scope') == parent_scope
		]
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
	# debug('before extract', obj={'results_count': len(results), 'extractor': extractor, 'key': ctx.get('key')}, sub='extractor')  # noqa: E501
	ancestor_id = ctx.get('ancestor_id')
	node_chain_start = ctx.get('node_chain_start', False)
	parent_scope = ctx.get('parent_scope')
	key = ctx.get('key')

	# Parse extractor, it can be a dict or a string (shortcut)
	parsed_extractor = parse_extractor(extractor)
	if not parsed_extractor:
		return results
	_type, _field, _condition, _group_by = parsed_extractor

	# Evaluate condition for each result
	if _condition:
		tmp_results = []
		if _type == 'target' and parent_scope:
			_condition = _condition + f' and item._context.get("scope") == "{parent_scope}"'
		elif ancestor_id and not node_chain_start:
			_condition = _condition + f' and item._context.get("ancestor_id") == "{str(ancestor_id)}"'
		for item in results:
			if item._type != _type:
				continue
			ctx['item'] = DotMap(item.toDict())
			ctx[f'{_type}'] = DotMap(item.toDict())
			safe_globals = {
				'__builtins__': {'len': len},
				're_match': lambda pattern, value: bool(re.search(pattern, str(value))) if value is not None else False,
			}
			_eval_condition = re.sub(r'([\w.]+)\s*~=\s*(.+?)(?=\s+(?:and|or)\s+|$)', r're_match(\2, \1)', _condition)
			eval_result = eval(_eval_condition, safe_globals, ctx)
			if eval_result:
				tmp_results.append(item)
			del ctx['item']
			del ctx[f'{_type}']
		# debug(f'kept {len(tmp_results)} / {len(results)} items after condition [bold]{_condition}[/bold]', sub='extractor')  # noqa: E501
		results = tmp_results
	else:
		results = [item for item in results if item._type == _type]
		if _type == 'target' and parent_scope:
			results = [item for item in results if item._context.get('scope') == parent_scope]
		elif ancestor_id and not node_chain_start:
			results = [item for item in results if item._context.get('ancestor_id') == ancestor_id]

	results_str = "\n".join([f'{repr(item)} [{str(item._context.get("ancestor_id", ""))}]' for item in results])
	debug(f'extracted results ([bold]ancestor_id[/]: {ancestor_id}, [bold]key[/]: {key}):\n{results_str}', sub='extractor')

	# Format field if needed
	if _field:
		already_formatted = '{' in _field and '}' in _field
		_field = '{' + _field + '}' if not already_formatted else _field

		if _group_by:
			already_formatted_gb = '{' in _group_by and '}' in _group_by
			_group_by = '{' + _group_by + '}' if not already_formatted_gb else _group_by
			groups = {}
			for item in results:
				item_dict = item.toDict()
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
			results = [v for v in (_format_nested(_field, item.toDict()) for item in results) if v]
	# debug('after extract', obj={'results_count': len(results), 'key': ctx.get('key')}, sub='extractor')
	return results


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
