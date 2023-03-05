from celery.result import AsyncResult, GroupResult
from rich.prompt import Confirm

from secsy.utils import deduplicate
from secsy.rich import console

def merge_extracted_values(results, opts):
	"""Run extractors and merge extracted values with option dict.

	Args:
		results (list): List of results.
		opts (dict): Options.

	Returns:
		tuple: targets, options.
	"""
	extractors = {k: v for k, v in opts.items() if k.endswith('_')}
	targets = None
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
		item for item in results if item['_type'] == _type and eval(_condition)
	]
	if _field:
		_field = '{' + _field + '}' if not _field.startswith('{') else _field
		return [_field.format(**item) for item in items]
	else:
		return items

def get_task_nodes(result, ids=[], nodes=[], level=0, parent=None):
	"""Get Celery task tree."""
	if result is None:
		return
	
	node = {
		'celery_id': result.id,
		'level': level,
		'parent': parent,
	}

	if isinstance(result, GroupResult):
		node['name'] = '_group'
		nodes.append(node)
		get_task_nodes(result.parent, ids=ids, nodes=nodes, level=level-1, parent=result.id)

	elif isinstance(result, AsyncResult):
		node['state'] = result.state
		node['info'] = result.info
		if result.id not in ids and len(result.args) > 1:
			ids.append(result.id)
			name = result.args[1]
			info = result.info
			chunk = info.get('chunk')
			chunk_count = info.get('chunk_count')
			if chunk:
				name += f' {chunk}/{chunk_count}'
			node['name'] = name
			node['state'] = result.state
			node['info']['results'] = [] # TODO: remove this
		nodes.append(node)

	# Browse children
	if result.children:
		for child in result.children:
			get_task_nodes(child, ids=ids, nodes=nodes, level=level+1, parent=result.id)

	# Browse parent
	get_task_nodes(result.parent, ids=ids, nodes=nodes, level=level-1, parent=result.id)

def get_task_ids(result, ids=[]):
	"""Get all Celery task ids recursively.

	Args:
		result (Union[AsyncResult, GroupResult]): Celery result object.
		ids (list): List of ids.
	"""
	if result is None:
		return

	if isinstance(result, GroupResult):
		get_task_ids(result.parent, ids=ids)

	elif isinstance(result, AsyncResult):
		if result.id not in ids:
			ids.append(result.id)

	# Browse children
	if result.children:
		for child in result.children:
			get_task_ids(child, ids=ids)

	# Browse parent
	get_task_ids(result.parent, ids=ids)


def get_task_info(task_id, debug=False):
	res = AsyncResult(task_id)
	data = {}
	if res.args and len(res.args) > 1:
		task_name = res.args[1]
		data['celery_task_id'] = task_id
		data['name'] = task_name
		data['state'] = res.state
		data['chunk_info'] = ''
		data['count'] = 0
		if res.info and not isinstance(res.info, list): # only available in RUNNING, SUCCESS, FAILURE states
			if isinstance(res.info, BaseException):
				data['error'] = str(res.info)
			else:
				chunk = res.info.get('chunk', '')
				chunk_count = res.info.get('chunk_count', '')
				if chunk:
					data['chunk_info'] = f'{chunk}/{chunk_count}'
				data.update(res.info)
	if debug:
		import json
		console.print_json(json.dumps(data))
	return data


def confirm_exit(func):
	def inner_function(self, *args, **kwargs):
		try:
			func(self, *args, **kwargs)
		except KeyboardInterrupt:
			exit_confirmed = Confirm.ask('Are you sure you want to exit ?')
			if exit_confirmed:
				self.log_results()
				raise KeyboardInterrupt
	return inner_function