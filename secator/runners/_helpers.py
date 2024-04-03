import os

from secator.utils import deduplicate


def run_extractors(results, opts, targets=[]):
	"""Run extractors and merge extracted values with option dict.

	Args:
		results (list): List of results.
		opts (dict): Options.
		targets (list): Original targets.

	Returns:
		tuple: targets, options.
	"""
	extractors = {k: v for k, v in opts.items() if k.endswith('_')}
	for key, val in extractors.items():
		key = key.rstrip('_')
		values = extract_from_results(results, val)
		if key == 'targets':
			targets = deduplicate(values)
		else:
			opts[key] = deduplicate(values)
	return targets, opts


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


def get_task_ids(result, ids=[]):
	"""Get all Celery task ids recursively.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result object.
		ids (list): List of ids.
	"""
	from celery.result import AsyncResult, GroupResult
	if result is None:
		return

	if isinstance(result, GroupResult):
		get_task_ids(result.parent, ids=ids)

	elif isinstance(result, AsyncResult):
		if result.id not in ids:
			ids.append(result.id)

	if hasattr(result, 'children') and result.children:
		for child in result.children:
			get_task_ids(child, ids=ids)

	# Browse parent
	if hasattr(result, 'parent') and result.parent:
		get_task_ids(result.parent, ids=ids)


def get_task_data(task_id):
	"""Get task info.

	Args:
		task_id (str): Celery task id.

	Returns:
		dict: Task info (id, name, state, results, chunk_info, count, error, ready).
	"""
	from celery.result import AsyncResult
	res = AsyncResult(task_id)
	if not (res and res.args and len(res.args) > 1):
		return
	data = {}
	task_name = res.args[1]
	data['id'] = task_id
	data['name'] = task_name
	data['state'] = res.state
	data['chunk_info'] = ''
	data['count'] = 0
	data['error'] = None
	data['ready'] = False
	data['descr'] = ''
	data['progress'] = 0
	data['results'] = []
	if res.state in ['FAILURE', 'SUCCESS', 'REVOKED']:
		data['ready'] = True
	if res.info and not isinstance(res.info, list):
		chunk = res.info.get('chunk', '')
		chunk_count = res.info.get('chunk_count', '')
		data['chunk'] = chunk
		data['chunk_count'] = chunk_count
		if chunk:
			data['chunk_info'] = f'{chunk}/{chunk_count}'
		data.update(res.info)
		data['descr'] = data.pop('description', '')
		# del data['results']
		# del data['task_results']
	return data


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
