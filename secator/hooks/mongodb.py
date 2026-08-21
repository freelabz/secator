import logging
import time

import pymongo
from bson.objectid import ObjectId
from celery import shared_task

from secator.config import CONFIG
from secator.hooks._dedup import compute_duplicate_updates
from secator.output_types import OUTPUT_TYPES, Warning, is_output_type
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


def ensure_mongo_run_id(context):
	"""Override the runner-core's uuid {type}_id with a Mongo ObjectId, in-place, on the FIRST DB
	write — so the runner doc _id (ObjectId({type}_id)) equals context.{type}_id and every finding
	scopes to that same id. Idempotent: a valid ObjectId is kept, so all later writes hit one doc.
	The json store keeps its uuid; only the mongodb path (which has bson) is coerced."""
	for key in ('task_id', 'workflow_id', 'scan_id', 'task_chunk_id'):
		val = context.get(key)
		if val and not ObjectId.is_valid(val):
			context[key] = str(ObjectId())


def update_runner(self):
	client = get_mongodb_client()
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	chunk = self.context.get(f'{type}_chunk_id') is not None
	ensure_mongo_run_id(self.context)
	update = self.toDict()
	key = f'{type}_chunk_id' if chunk else f'{type}_id'
	_id = ObjectId(self.context.get(key))
	debug('to_update', sub='hooks.mongodb', id=str(_id), obj=get_runner_dbg(self), obj_after=True, obj_breaklines=False, verbose=True)  # noqa: E501
	start_time = time.time()
	try:
		db[collection].update_one({'_id': _id}, {'$set': update}, upsert=True)
		elapsed = time.time() - start_time
		debug(f'in {elapsed:.4f}s', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=False)
		self.last_updated_db = start_time
	except pymongo.errors.DocumentTooLarge:
		# The runner state exceeds MongoDB's 16MB BSON limit (usually huge outputs).
		# Don't crash the runner over a persistence limit — warn and carry on.
		msg = f'{self.unique_name} state exceeds MongoDB\'s 16MB document limit; skipping this DB update.'
		# Persisted to the store via the runner's on_item hook (warning is tiny; no recursion).
		self.add_result(Warning(message=msg))
		debug(msg, sub='hooks.mongodb', id=_id)


def build_pending_doc(parent, task_spec, child_type):
	"""Minimal PENDING placeholder doc for a not-yet-run child runner.

	The runtime update_runner does {'$set': self.toDict()} and fully overwrites
	this once the child executes, so only the fields the UI tree / watchdog need
	before that have to be correct here.
	"""
	return {
		'name': task_spec.get('name'),
		'status': 'PENDING',
		'done': False,
		'config': {'type': child_type, 'name': task_spec.get('name')},
		'context': dict(task_spec.get('context', {})),
		'has_parent': True,
		'chunk': task_spec.get('chunk'),
		'chunk_count': task_spec.get('chunk_count'),
	}


def on_build(self, task_spec):
	"""Build-time hook: mint the child runner's Mongo doc + id before dispatch.

	Fired by the PARENT runner (self) while assembling the Celery canvas, once
	per child task/workflow/chunk. Inserts a PENDING placeholder and writes its
	id into the child signature's serialized context so a redelivered task
	reuses the same doc (update_one) instead of inserting a new one.
	"""
	client = get_mongodb_client()
	db = client.main
	parent_type = self.config.type
	child_type = 'workflow' if parent_type == 'scan' else 'task'
	collection = f'{child_type}s'
	is_chunk = bool(task_spec.get('chunk'))
	key = f'{child_type}_chunk_id' if is_chunk else f'{child_type}_id'
	child_id = str(ObjectId())
	task_spec.setdefault('context', {})[key] = child_id
	doc = build_pending_doc(self, task_spec, child_type)  # doc.context now carries child_id
	db[collection].insert_one({**doc, '_id': ObjectId(child_id)})
	return task_spec


def update_finding(self, item):
	if not is_output_type(item):
		return item
	ensure_mongo_run_id(self.context)
	for key in (f'{self.config.type}_id', f'{self.config.type}_chunk_id'):
		cur = item._context.get(key)
		if cur and not ObjectId.is_valid(cur):
			item._context[key] = self.context.get(key)
	start_time = time.time()
	client = get_mongodb_client()
	db = client.main
	update = item.toDict()
	_type = item._type
	_id = ObjectId(item._uuid) if ObjectId.is_valid(item._uuid) else None
	try:
		if _id:
			finding = db['findings'].update_one({'_id': _id}, {'$set': update})
			status = 'UPDATED'
		else:
			# Stamp an explicit untagged default so tag_duplicates can index-seek untagged
			# findings (`_tagged: False`) instead of a `$ne: True` whole-workspace scan (#1315).
			update.setdefault('_tagged', False)
			finding = db['findings'].insert_one(update)
			item._uuid = str(finding.inserted_id)
			status = 'CREATED'
	except pymongo.errors.DocumentTooLarge:
		# The finding exceeds MongoDB's 16MB BSON limit (usually huge outputs).
		# Don't crash the runner over a persistence limit — warn and carry on.
		msg = f'{item._type} finding exceeds MongoDB\'s 16MB document limit; skipping persist.'
		# Persisted to the store via the runner's on_item hook (warning is tiny; no recursion).
		self.add_result(Warning(message=msg))
		debug(msg, sub='hooks.mongodb', id=str(item._uuid))
		return item
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
	from secator.definitions import IN_WORKER
	ws_id = self.toDict().get('context', {}).get('workspace_id')
	if not ws_id:
		return
	if not IN_WORKER:
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
	# `$in: [False, None]` (index-seekable) instead of `$ne: True` (whole-workspace scan). Matches
	# findings stamped `_tagged: False` on insert AND legacy docs where the field is absent (indexed
	# as null), so no backfill is required. See #1315.
	untagged_query = {'_context.workspace_id': str(ws_id), '_tagged': {'$in': [False, None]}}
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
	db_updates = compute_duplicate_updates(
		workspace_findings,
		untagged_findings,
		CONFIG.addons.mongodb.duplicate_main_copy_fields,
	)
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
		'on_build': [on_build],
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_build': [on_build],
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_build': [on_build],
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner],
	}
}
