import logging
import time

from bson.objectid import ObjectId
from celery import shared_task

from secator.config import CONFIG
from secator.drivers._base import Driver
from secator.output_types import OUTPUT_TYPES
from secator.utils import debug, escape_mongodb_url

logger = logging.getLogger(__name__)

_mongodb_clients = {}


def get_mongodb_client(url=None):
	"""Get or create MongoDB client (module-level singleton per URL, not pickled with driver instances)."""
	global _mongodb_clients
	resolved_url = escape_mongodb_url(url or CONFIG.addons.mongodb.url)
	if resolved_url not in _mongodb_clients:
		import pymongo
		_mongodb_clients[resolved_url] = pymongo.MongoClient(
			resolved_url,
			maxPoolSize=CONFIG.addons.mongodb.max_pool_size,
			serverSelectionTimeoutMS=CONFIG.addons.mongodb.server_selection_timeout_ms,
			connect=False,
			tz_aware=True
		)
	return _mongodb_clients[resolved_url]


def get_runner_dbg(runner):
	"""Runner debug object."""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


def load_finding(obj, exclude_types=[]):
	from secator.output_types import OUTPUT_TYPES
	finding_type = obj['_type']
	if finding_type in exclude_types:
		return None
	for otype in OUTPUT_TYPES:
		oname = otype.get_name()
		if finding_type == oname:
			item = otype.load(obj)
			item._uuid = str(obj['_id'])
			return item
	return None


def load_findings(objs, exclude_types=[]):
	findings = [load_finding(obj, exclude_types) for obj in objs]
	return [f for f in findings if f is not None]


def get_results(uuids):
	"""Get results from MongoDB based on a list of uuids.

	Args:
		uuids (list[str | Output]): List of uuids, but can also be a mix of uuids and output types.

	Returns:
		Generator of findings.
	"""
	client = get_mongodb_client()
	db = client.main
	del_uuids = []
	for r in uuids:
		if isinstance(r, tuple(OUTPUT_TYPES)):
			yield r
			del_uuids.append(r)
	uuids = [ObjectId(u) for u in uuids if u not in del_uuids and ObjectId.is_valid(u)]
	for r in db.findings.find({'_id': {'$in': uuids}}):
		finding = load_finding(r)
		yield finding


@shared_task
def tag_duplicates(ws_id=None, full_scan=False, exclude_types=[], max_items=CONFIG.addons.mongodb.max_items, log_hook=None):  # noqa: E501
	"""Tag duplicates in workspace.

	Args:
		ws_id (str): Workspace id.
		full_scan (bool): If True, scan all findings, otherwise only untagged findings.
	"""
	debug(f'running duplicate check on workspace {ws_id}', sub='drivers.mongodb', log_hook=log_hook)
	init_time = time.time()
	client = get_mongodb_client()
	db = client.main
	start_time = time.time()
	workspace_query = {'_context.workspace_id': str(ws_id), '_context.workspace_duplicate': False, '_tagged': True}
	untagged_query = {'_context.workspace_id': str(ws_id), '_tagged': {'$ne': True}}
	if full_scan:
		del untagged_query['_tagged']
	workspace_findings = load_findings(list(db.findings.find(workspace_query).sort('_timestamp', -1)), exclude_types)
	untagged_query_cursor = db.findings.find(untagged_query).sort('_timestamp', -1)
	if max_items != -1:
		debug(f'Limiting untagged query to {max_items} items', sub='drivers.mongodb', log_hook=log_hook)
		untagged_query_cursor = untagged_query_cursor.limit(max_items)
	untagged_findings = load_findings(list(untagged_query_cursor), exclude_types)
	debug(
		f'Workspace non-duplicates findings: {len(workspace_findings)} '
		f'Untagged findings: {len(untagged_findings)}. Max items: {max_items}. Excluded types: {exclude_types}. '
		f'Query time: {time.time() - start_time}s',
		sub='drivers.mongodb',
		log_hook=log_hook
	)
	start_time = time.time()
	seen = []
	db_updates = {}

	for item in untagged_findings:
		if item._uuid in seen:
			continue

		debug(
			f'Processing: {repr(item)} ({item._timestamp}) [{item._uuid}]',
			sub='drivers.mongodb',
			verbose=True,
			log_hook=log_hook
		)

		duplicate_ids = [
			_._uuid
			for _ in untagged_findings
			if _ == item and _._uuid != item._uuid
		]
		seen.extend(duplicate_ids)

		debug(
			f'Found {len(duplicate_ids)} duplicates for item',
			sub='drivers.mongodb',
			verbose=True,
			log_hook=log_hook
		)

		duplicate_ws = [
			_ for _ in workspace_findings
			if _ == item and _._uuid != item._uuid
		]
		debug(f' --> Found {len(duplicate_ws)} workspace duplicates for item', sub='drivers.mongodb', verbose=True, log_hook=log_hook)  # noqa: E501

		copied_fields = {}
		for previous_item in duplicate_ws:
			copy_fields = CONFIG.addons.mongodb.duplicate_main_copy_fields
			if copy_fields:
				for field in copy_fields:
					if not hasattr(previous_item, field):
						debug(f'{field} not found on {previous_item._uuid}', sub='drivers.mongodb', verbose=True, log_hook=log_hook)
						continue
					value_prev = getattr(previous_item, field)
					debug(f'{field} is {value_prev} on {previous_item._uuid}', sub='drivers.mongodb', verbose=True, log_hook=log_hook)
					if not value_prev:
						debug(f'{field} is empty on {previous_item._uuid}', sub='drivers.mongodb', verbose=True, log_hook=log_hook)
						continue
					value_curr = getattr(item, field)
					debug(f'{field} is {value_curr} on {item._uuid}', sub='drivers.mongodb', verbose=True, log_hook=log_hook)
					if not value_curr:
						if field in copied_fields:
							debug(f'{field} is already copied from previous item', sub='drivers.mongodb', verbose=True, log_hook=log_hook)
							continue
						debug(f'Using {field}={value_prev} from {previous_item._uuid} for {item._uuid}', sub='drivers.mongodb', verbose=True, log_hook=log_hook)  # noqa: E501
						copied_fields[field] = value_prev

		related_ids = []
		if duplicate_ws:
			duplicate_ws_ids = [_._uuid for _ in duplicate_ws]
			duplicate_ids.extend(duplicate_ws_ids)
			for related in duplicate_ws:
				related_ids.extend(related._related)

		debug(f' --> Found {len(duplicate_ids)} total duplicates for item', sub='drivers.mongodb', verbose=True, log_hook=log_hook)  # noqa: E501

		db_updates[item._uuid] = {
			**copied_fields,
			'_related': duplicate_ids + related_ids,
			'_context.workspace_duplicate': False,
			'_tagged': True
		}
		for uuid in duplicate_ids:
			db_updates[uuid] = {
				'_context.workspace_duplicate': True,
				'_tagged': True
			}
	debug(f'Finished processing untagged findings in {time.time() - start_time}s', sub='drivers.mongodb', log_hook=log_hook)
	start_time = time.time()

	debug(f'Executing {len(db_updates)} database updates', sub='drivers.mongodb', log_hook=log_hook)

	from pymongo import UpdateOne
	if not db_updates:
		debug('no db updates to execute', sub='drivers.mongodb', log_hook=log_hook)
		return

	result = db.findings.bulk_write(
		[UpdateOne({'_id': ObjectId(uuid)}, {'$set': update}) for uuid, update in db_updates.items()]
	)
	debug(result, sub='drivers.mongodb', log_hook=log_hook)
	debug(f'Finished running db update in {time.time() - start_time}s', sub='drivers.mongodb', log_hook=log_hook)
	debug(f'Finished running tag duplicates in {time.time() - init_time}s', sub='drivers.mongodb', log_hook=log_hook)


class MongoDBDriver(Driver):
	"""MongoDB driver. Persists runner state and findings to a MongoDB database."""

	def __init__(self, url=None):
		self.url = url or CONFIG.addons.mongodb.url

	@property
	def hooks(self):
		from secator.runners import Scan, Task, Workflow
		return {
			Scan: {
				'on_init': [self.update_runner],
				'on_start': [self.update_runner],
				'on_interval': [self.update_runner],
				'on_duplicate': [self.update_finding],
				'on_end': [self.update_runner],
			},
			Workflow: {
				'on_init': [self.update_runner],
				'on_start': [self.update_runner],
				'on_interval': [self.update_runner],
				'on_duplicate': [self.update_finding],
				'on_end': [self.update_runner],
			},
			Task: {
				'on_init': [self.update_runner],
				'on_start': [self.update_runner],
				'on_item': [self.update_finding],
				'on_duplicate': [self.update_finding],
				'on_interval': [self.update_runner],
				'on_end': [self.update_runner],
			}
		}

	def check(self) -> bool:
		return bool(self.url)

	def update_runner(self, runner):
		client = get_mongodb_client(self.url)
		db = client.main
		type = runner.config.type
		collection = f'{type}s'
		update = runner.toDict()
		chunk = update.get('chunk')
		_id = runner.context.get(f'{type}_chunk_id') if chunk else runner.context.get(f'{type}_id')
		debug('to_update', sub='drivers.mongodb', id=_id, obj=get_runner_dbg(runner), obj_after=True, obj_breaklines=False, verbose=True)  # noqa: E501
		start_time = time.time()
		if _id:
			db[collection].update_one({'_id': ObjectId(_id)}, {'$set': update})
			elapsed = time.time() - start_time
			debug(
				f'[dim gold4]updated in {elapsed:.4f}s[/]', sub='drivers.mongodb', id=_id, obj=get_runner_dbg(runner), obj_after=False)  # noqa: E501
			runner.last_updated_db = start_time
		else:
			result = db[collection].insert_one(update)
			_id = str(result.inserted_id)
			if chunk:
				runner.context[f'{type}_chunk_id'] = _id
			else:
				runner.context[f'{type}_id'] = _id
			elapsed = time.time() - start_time
			debug(f'in {elapsed:.4f}s', sub='drivers.mongodb', id=_id, obj=get_runner_dbg(runner), obj_after=False)

	def update_finding(self, runner, item):
		if type(item) not in OUTPUT_TYPES:
			return item
		start_time = time.time()
		client = get_mongodb_client(self.url)
		db = client.main
		update = item.toDict()
		_type = item._type
		_id = ObjectId(item._uuid) if ObjectId.is_valid(item._uuid) else None
		if _id:
			db['findings'].update_one({'_id': _id}, {'$set': update})
			status = 'UPDATED'
		else:
			result = db['findings'].insert_one(update)
			item._uuid = str(result.inserted_id)
			status = 'CREATED'
		elapsed = time.time() - start_time
		debug_obj = {
			_type: status,
			'type': 'finding',
			'class': runner.__class__.__name__,
			'caller': runner.config.name,
			**runner.context
		}
		debug(f'in {elapsed:.4f}s', sub='drivers.mongodb', id=str(item._uuid), obj=debug_obj, obj_after=False)
		return item

	def find_duplicates(self, runner):
		from secator.definitions import IN_WORKER
		ws_id = runner.toDict().get('context', {}).get('workspace_id')
		if not ws_id:
			return
		if not IN_WORKER:
			tag_duplicates(ws_id)
		else:
			tag_duplicates.delay(ws_id)
