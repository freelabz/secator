import os

import kombu
import kombu.exceptions

from secator.utils import deduplicate
from secator.rich import console


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

	try:
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
	except kombu.exceptions.DecodeError as e:
		console.print(f'[bold red]{str(e)}. Aborting get_task_ids.[/]')
		return


def get_task_data(task_id):
	"""Get task info.

	Args:
		task_id (str): Celery task id.

	Returns:
		dict: Task info (id, name, state, results, chunk_info, count, error, ready).
	"""
	from celery.result import AsyncResult
	res = AsyncResult(task_id)
	if not res:
		return
	try:
		args = res.args
		info = res.info
		state = res.state
	except kombu.exceptions.DecodeError as e:
		console.print(f'[bold red]{str(e)}. Aborting get_task_data.[/]')
		return
	if not (args and len(args) > 1):
		return
	task_name = args[1]
	data = {
		'id': task_id,
		'name': task_name,
		'state': state,
		'chunk_info': '',
		'count': 0,
		'error': None,
		'ready': False,
		'descr': '',
		'progress': 0,
		'results': []
	}

	# Set ready flag
	if state in ['FAILURE', 'SUCCESS', 'REVOKED']:
		data['ready'] = True

	# Set task data
	if info and not isinstance(info, list):
		data.update(info)
		chunk = data.get('chunk')
		chunk_count = data.get('chunk_count')
		if chunk and chunk_count:
			data['chunk_info'] = f'{chunk}/{chunk_count}'
		data['descr'] = data.pop('description', '')
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
