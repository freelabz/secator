import os

from secator.utils import deduplicate


def run_extractors(results, opts, inputs=[]):
	"""Run extractors and merge extracted values with option dict.

	Args:
		results (list): List of results.
		opts (dict): Options.
		inputs (list): Original inputs.

	Returns:
		tuple: inputs, options.
	"""
	extractors = {k: v for k, v in opts.items() if k.endswith('_')}
	for key, val in extractors.items():
		key = key.rstrip('_')
		values = extract_from_results(results, val)
		if key == 'targets':
			inputs = deduplicate(values)
		else:
			opts[key] = deduplicate(values)
	return inputs, opts


def extract_from_results(results, extractors):
	"""Extract sub extractors from list of results dict.

	Args:
		results (list): List of dict.
		extractors (list): List of extractors to extract from.

	Returns:
		list: List of extracted results (flat).
	"""
	extracted = []
	if not isinstance(extractors, list):
		extractors = [extractors]
	for extractor in extractors:
		extracted.extend(process_extractor(results, extractor))
	return extracted


def process_extractor(results, extractor, ctx={}):
	"""Process extractor.

	Args:
		results (list): List of results.
		extractor (dict / str): extractor definition.

	Returns:
		list: List of extracted results.
	"""
	if isinstance(extractor, dict):
		_type = extractor['type']
		_field = extractor.get('field')
		_condition = extractor.get('condition', 'True')
	else:
		_type, _field = tuple(extractor.split('.'))
		_condition = 'True'
	items = [
		item for item in results if item._type == _type and eval(_condition)
	]
	if _field:
		_field = '{' + _field + '}' if not _field.startswith('{') else _field
		items = [_field.format(**item.toDict()) for item in items]
	return items


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
