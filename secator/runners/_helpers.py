import os

from secator.output_types import Error
from secator.utils import deduplicate, debug


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
	_type, _field, _condition = parsed_extractor
	s = f'{_type}.{_field}'
	if _condition:
		s = f'{s} if {_condition}'
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
		tuple|None: type, field, condition or None if invalid.
	"""
	# Parse extractor, it can be a dict or a string (shortcut)
	if isinstance(extractor, dict):
		_type = extractor['type']
		_field = extractor.get('field')
		_condition = extractor.get('condition')
	else:
		parts = tuple(extractor.split('.'))
		if len(parts) == 2:
			_type = parts[0]
			_field = parts[1]
			_condition = None
		else:
			return None
	return _type, _field, _condition


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
	key = ctx.get('key')

	# Parse extractor, it can be a dict or a string (shortcut)
	parsed_extractor = parse_extractor(extractor)
	if not parsed_extractor:
		return results
	_type, _field, _condition = parsed_extractor

	# Evaluate condition for each result
	if _condition:
		tmp_results = []
		if ancestor_id:
			_condition = _condition + f' and item._context.get("ancestor_id") == "{str(ancestor_id)}"'
		for item in results:
			if item._type != _type:
				continue
			ctx['item'] = item
			ctx[f'{_type}'] = item
			safe_globals = {'__builtins__': {'len': len}}
			eval_result = eval(_condition, safe_globals, ctx)
			if eval_result:
				tmp_results.append(item)
			del ctx['item']
			del ctx[f'{_type}']
		# debug(f'kept {len(tmp_results)} / {len(results)} items after condition [bold]{_condition}[/bold]', sub='extractor')  # noqa: E501
		results = tmp_results
	else:
		results = [item for item in results if item._type == _type]
		if ancestor_id:
			results = [item for item in results if item._context.get('ancestor_id') == ancestor_id]

	results_str = "\n".join([f'{repr(item)} [{str(item._context.get("ancestor_id", ""))}]' for item in results])
	debug(f'extracted results ([bold]ancestor_id[/]: {ancestor_id}, [bold]key[/]: {key}):\n{results_str}', sub='extractor')

	# Format field if needed
	if _field:
		already_formatted = '{' in _field and '}' in _field
		_field = '{' + _field + '}' if not already_formatted else _field
		results = [_field.format(**item.toDict()) for item in results]
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
