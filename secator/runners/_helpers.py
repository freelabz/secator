import os

from secator.output_types import Error
from secator.utils import deduplicate, debug


def run_extractors(results, opts, inputs=[], ctx={}, dry_run=False):
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
	extractors = {k: v for k, v in opts.items() if k.endswith('_')}
	errors = []
	computed_inputs = []
	computed_opts = {}
	for key, val in extractors.items():
		key = key.rstrip('_')
		ctx['key'] = key
		values, err = extract_from_results(results, val, ctx=ctx)
		errors.extend(err)
		if key == 'targets':
			targets = [fmt_extractor(v) for v in val] if dry_run else deduplicate(values)
			computed_inputs.extend(targets)
			ctx['targets'] = computed_inputs
		else:
			computed_opt = [fmt_extractor(v) for v in val] if dry_run else deduplicate(values)
			if computed_opt:
				computed_opts[key] = computed_opt
				opts[key] = computed_opts[key]
	if computed_inputs:
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


def extract_from_results(results, extractors, ctx={}):
	"""Extract sub extractors from list of results dict.

	Args:
		results (list): List of dict.
		extractors (list): List of extractors to extract from.
		ctx (dict, optional): Context.

	Returns:
		tuple: List of extracted results (flat), list of errors.
	"""
	all_results = []
	errors = []
	if not isinstance(extractors, list):
		extractors = [extractors]
	for extractor in extractors:
		try:
			extractor_results = process_extractor(results, extractor, ctx=ctx)
			all_results.extend(extractor_results)
		except Exception as e:
			error = Error.from_exception(e)
			errors.append(error)
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


def process_extractor(results, extractor, ctx={}):
	"""Process extractor.

	Args:
		results (list): List of results.
		extractor (dict / str): extractor definition.

	Returns:
		list: List of extracted results.
	"""
	debug('before extract', obj={'results_count': len(results), 'extractor': extractor, 'key': ctx.get('key')}, sub='extractor')  # noqa: E501

	# Parse extractor, it can be a dict or a string (shortcut)
	parsed_extractor = parse_extractor(extractor)
	if not parsed_extractor:
		return results
	_type, _field, _condition = parsed_extractor

	# Evaluate condition for each result
	if _condition:
		tmp_results = []
		for item in results:
			if not item._type == _type:
				continue
			ctx['item'] = item
			ctx[f'{_type}'] = item
			safe_globals = {'__builtins__': {'len': len}}
			eval_result = eval(_condition, safe_globals, ctx)
			if eval_result:
				tmp_results.append(item)
			del ctx['item']
			del ctx[f'{_type}']
		debug(f'kept {len(tmp_results)} out of {len(results)} items after condition [bold]{_condition}[/bold]', sub='extractor')  # noqa: E501
		results = tmp_results
	else:
		results = [item for item in results if item._type == _type]

	# Format field if needed
	if _field:
		already_formatted = '{' in _field and '}' in _field
		_field = '{' + _field + '}' if not already_formatted else _field
		results = [_field.format(**item.toDict()) for item in results]
	debug('after extract', obj={'results_count': len(results), 'key': ctx.get('key')}, sub='extractor')
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
