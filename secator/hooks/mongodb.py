import logging
import time
from dataclasses import fields as dataclass_fields

import pymongo
from bson.objectid import ObjectId
from celery import shared_task

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug, escape_mongodb_url

# import gevent.monkey
# gevent.monkey.patch_all()

MONGODB_URL = CONFIG.addons.mongodb.url
MONGODB_UPDATE_FREQUENCY = CONFIG.addons.mongodb.update_frequency
MONGODB_CONNECT_TIMEOUT = CONFIG.addons.mongodb.server_selection_timeout_ms
MONGODB_MAX_POOL_SIZE = CONFIG.addons.mongodb.max_pool_size

logger = logging.getLogger(__name__)

_mongodb_client = None


def get_mongodb_client():
	"""Get or create MongoDB client"""
	global _mongodb_client
	if _mongodb_client is None:
		_mongodb_client = pymongo.MongoClient(
			escape_mongodb_url(MONGODB_URL),
			maxPoolSize=MONGODB_MAX_POOL_SIZE,
			serverSelectionTimeoutMS=MONGODB_CONNECT_TIMEOUT,
			connect=False,
			tz_aware=True
		)
	return _mongodb_client


def get_runner_dbg(runner):
	"""Runner debug object"""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


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


def update_runner(self):
	client = get_mongodb_client()
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	update = self.toDict()
	chunk = update.get('chunk')
	_id = self.context.get(f'{type}_chunk_id') if chunk else self.context.get(f'{type}_id')
	debug('to_update', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=True, obj_breaklines=False, verbose=True)  # noqa: E501
	start_time = time.time()
	if _id:
		db = client.main
		start_time = time.time()
		db[collection].update_one({'_id': ObjectId(_id)}, {'$set': update})
		end_time = time.time()
		elapsed = end_time - start_time
		debug(
			f'[dim gold4]updated in {elapsed:.4f}s[/]', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=False)  # noqa: E501
		self.last_updated_db = start_time
	else:  # sync update and save result to runner object
		runner = db[collection].insert_one(update)
		_id = str(runner.inserted_id)
		if chunk:
			self.context[f'{type}_chunk_id'] = _id
		else:
			self.context[f'{type}_id'] = _id
		end_time = time.time()
		elapsed = end_time - start_time
		debug(f'in {elapsed:.4f}s', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=False)


def _has_new_items(existing_list, new_list):
	"""Check if new_list contains items not in existing_list.

	Args:
		existing_list: The existing list to check against
		new_list: The new list to check

	Returns:
		bool: True if new_list has items not in existing_list
	"""
	try:
		existing_set = set(existing_list)
		for item_val in new_list:
			if item_val not in existing_set:
				return True
	except TypeError:
		# Items not hashable, use slower check
		for item_val in new_list:
			if item_val not in existing_list:
				return True
	return False


def _merge_lists(existing_list, new_list):
	"""Merge two lists, avoiding duplicates while preserving order.

	Note: This function modifies existing_list in-place by appending new items from new_list.
	Callers should pass a copy if they want to preserve the original list.

	Args:
		existing_list: The existing list to merge into (modified in-place)
		new_list: The new list to merge from

	Returns:
		The merged list (same object as existing_list)
	"""
	# Try to use set for O(1) lookup if items are hashable
	try:
		existing_set = set(existing_list)
		for item_val in new_list:
			if item_val not in existing_set:
				existing_list.append(item_val)
				existing_set.add(item_val)
	except TypeError:
		# Items are not hashable (e.g., dicts), fall back to O(n) check
		for item_val in new_list:
			if item_val not in existing_list:
				existing_list.append(item_val)
	return existing_list


def update_finding(self, item):
	if type(item) not in OUTPUT_TYPES:
		return item
	start_time = time.time()
	client = get_mongodb_client()
	db = client.main
	update = item.toDict()
	_type = item._type
	_id = ObjectId(item._uuid) if ObjectId.is_valid(item._uuid) else None
	if _id:
		finding = db['findings'].update_one({'_id': _id}, {'$set': update})
		status = 'UPDATED'
	else:
		# Check if a duplicate already exists in MongoDB
		# Build query based on fields that are used for comparison
		query = {'_type': _type}

		# Add workspace_id to query if present to scope duplicates to workspace
		workspace_id = getattr(item, '_context', {}).get('workspace_id') if hasattr(item, '_context') else None
		if workspace_id:
			query['_context.workspace_id'] = workspace_id

		# Get fields that are used for comparison (compare != False)
		item_class = type(item)
		for field in dataclass_fields(item_class):
			if field.compare and not field.name.startswith('_'):
				field_value = getattr(item, field.name)
				# Include all non-None, non-empty values in query (including False and 0)
				# Empty strings, lists, and dicts are excluded as they're not meaningful for duplicate detection
				if field_value is not None and field_value != '':
					# Skip empty lists and dicts
					if isinstance(field_value, (list, dict)) and len(field_value) == 0:
						continue
					query[field.name] = field_value

		# Look for existing finding with same identifying fields
		existing = db['findings'].find_one(query)

		if existing:
			# Update existing record instead of creating new one
			_id = existing['_id']
			# Track which fields actually changed
			changed_fields = {}
			for key, value in update.items():
				# Always update special fields that may be modified
				if key in ('_timestamp', '_tagged', '_duplicate', '_related', '_source'):
					changed_fields[key] = value
					continue
				# Skip None values - keep existing value
				if value is None:
					continue
				# Skip empty strings if existing value is non-empty
				existing_value = existing.get(key)
				if value == '' and existing_value and existing_value != '':
					continue
				# Skip empty lists or dicts if existing value is non-empty
				if isinstance(value, (list, dict)) and len(value) == 0:
					if isinstance(existing_value, (list, dict)) and len(existing_value) > 0:
						continue
				# For lists, merge them (avoiding duplicates)
				if isinstance(value, list) and isinstance(existing_value, list):
					# Only merge and mark as changed if there are new items
					if _has_new_items(existing_value, value):
						merged_list = _merge_lists(existing_value.copy(), value)
						changed_fields[key] = merged_list
				# For dicts, merge them
				elif isinstance(value, dict) and isinstance(existing_value, dict):
					merged_dict = existing_value.copy()
					merged_dict.update(value)
					# Only mark as changed if dict actually changed
					if merged_dict != existing_value:
						changed_fields[key] = merged_dict
				else:
					# Only update if value is different
					if existing.get(key) != value:
						changed_fields[key] = value
			# Only update if there are actual changes
			if changed_fields:
				db['findings'].update_one({'_id': _id}, {'$set': changed_fields})
			item._uuid = str(_id)
			status = 'UPDATED'
			debug('found existing finding in db, updating', sub='hooks.mongodb', id=str(_id), verbose=True)
		else:
			finding = db['findings'].insert_one(update)
			item._uuid = str(finding.inserted_id)
			status = 'CREATED'
	end_time = time.time()
	elapsed = end_time - start_time
	debug_obj = {
		_type: status,
		'type': 'finding',
		'class': self.__class__.__name__,
		'caller': self.config.name,
		**self.context
	}
	debug(f'in {elapsed:.4f}s', sub='hooks.mongodb', id=str(item._uuid), obj=debug_obj, obj_after=False)  # noqa: E501
	return item


def find_duplicates(self):
	from secator.celery import IN_CELERY_WORKER_PROCESS
	ws_id = self.toDict().get('context', {}).get('workspace_id')
	if not ws_id:
		return
	if not IN_CELERY_WORKER_PROCESS:
		tag_duplicates(ws_id)
	else:
		tag_duplicates.delay(ws_id)


def load_finding(obj, exclude_types=[]):
	finding_type = obj['_type']
	if finding_type in exclude_types:
		return None
	klass = None
	for otype in OUTPUT_TYPES:
		oname = otype.get_name()
		if finding_type == oname:
			klass = otype
			item = klass.load(obj)
			item._uuid = str(obj['_id'])
			return item
	return None


def load_findings(objs, exclude_types=[]):
	findings = [load_finding(obj, exclude_types) for obj in objs]
	return [f for f in findings if f is not None]


@shared_task
def tag_duplicates(ws_id: str = None, full_scan: bool = False, exclude_types=[], max_items=CONFIG.addons.mongodb.max_items, log_hook=None):  # noqa: E501
	"""Tag duplicates in workspace.

	Args:
		ws_id (str): Workspace id.
		full_scan (bool): If True, scan all findings, otherwise only untagged findings.
	"""
	debug(f'running duplicate check on workspace {ws_id}', sub='hooks.mongodb', log_hook=log_hook)
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
		debug(f'Limiting untagged query to {max_items} items', sub='hooks.mongodb', log_hook=log_hook)
		untagged_query_cursor = untagged_query_cursor.limit(max_items)
	untagged_findings = load_findings(list(untagged_query_cursor), exclude_types)
	debug(
		f'Workspace non-duplicates findings: {len(workspace_findings)} '
		f'Untagged findings: {len(untagged_findings)}. Max items: {max_items}. Excluded types: {exclude_types}. '
		f'Query time: {time.time() - start_time}s',
		sub='hooks.mongodb',
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
			sub='hooks.mongodb',
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
			sub='hooks.mongodb',
			verbose=True,
			log_hook=log_hook
		)

		duplicate_ws = [
			_ for _ in workspace_findings
			if _ == item and _._uuid != item._uuid
		]
		debug(f' --> Found {len(duplicate_ws)} workspace duplicates for item', sub='hooks.mongodb', verbose=True, log_hook=log_hook)  # noqa: E501

		# Copy selected fields from the previous "main" finding (first workspace duplicate)
		# into the new main finding, if configured.
		copied_fields = {}
		for previous_item in duplicate_ws:
			copy_fields = CONFIG.addons.mongodb.duplicate_main_copy_fields
			if copy_fields:
				for field in copy_fields:
					# Only copy if the attribute exists on the previous finding
					if not hasattr(previous_item, field):
						debug(f'{field} not found on {previous_item._uuid}', sub='hooks.mongodb', verbose=True, log_hook=log_hook)
						continue
					value_prev = getattr(previous_item, field)
					debug(f'{field} is {value_prev} on {previous_item._uuid}', sub='hooks.mongodb', verbose=True, log_hook=log_hook)
					# Skip empty values to avoid overwriting with "less useful" data
					if not value_prev:
						debug(f'{field} is empty on {previous_item._uuid}', sub='hooks.mongodb', verbose=True, log_hook=log_hook)
						continue
					# Only overwrite if current item field isn't set
					value_curr = getattr(item, field)
					debug(f'{field} is {value_curr} on {item._uuid}', sub='hooks.mongodb', verbose=True, log_hook=log_hook)
					if not value_curr:
						if field in copied_fields:
							debug(f'{field} is already copied from previous item', sub='hooks.mongodb', verbose=True, log_hook=log_hook)
							continue
						debug(f'Using {field}={value_prev} from {previous_item._uuid} for {item._uuid}', sub='hooks.mongodb', verbose=True, log_hook=log_hook)  # noqa: E501
						copied_fields[field] = value_prev

		related_ids = []
		if duplicate_ws:
			duplicate_ws_ids = [_._uuid for _ in duplicate_ws]
			duplicate_ids.extend(duplicate_ws_ids)
			for related in duplicate_ws:
				related_ids.extend(related._related)

		debug(f' --> Found {len(duplicate_ids)} total duplicates for item', sub='hooks.mongodb', verbose=True, log_hook=log_hook)  # noqa: E501

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
	debug(f'Finished processing untagged findings in {time.time() - start_time}s', sub='hooks.mongodb', log_hook=log_hook)
	start_time = time.time()

	debug(f'Executing {len(db_updates)} database updates', sub='hooks.mongodb', log_hook=log_hook)

	from pymongo import UpdateOne
	if not db_updates:
		debug('no db updates to execute', sub='hooks.mongodb', log_hook=log_hook)
		return

	result = db.findings.bulk_write(
		[UpdateOne({'_id': ObjectId(uuid)}, {'$set': update}) for uuid, update in db_updates.items()]
	)
	debug(result, sub='hooks.mongodb', log_hook=log_hook)
	debug(f'Finished running db update in {time.time() - start_time}s', sub='hooks.mongodb', log_hook=log_hook)
	debug(f'Finished running tag duplicates in {time.time() - init_time}s', sub='hooks.mongodb', log_hook=log_hook)


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner]
	}
}
