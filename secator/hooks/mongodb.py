import logging
import time

import pymongo
from bson.objectid import ObjectId
from celery import shared_task

from secator.config import CONFIG
from secator.hooks._dedup import compute_duplicate_updates
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug, escape_mongodb_url, should_update

# import gevent.monkey
# gevent.monkey.patch_all()

MONGODB_URL = CONFIG.addons.mongodb.url
MONGODB_UPDATE_FREQUENCY = CONFIG.addons.mongodb.update_frequency
MONGODB_CONNECT_TIMEOUT = CONFIG.addons.mongodb.server_selection_timeout_ms
MONGODB_MAX_POOL_SIZE = CONFIG.addons.mongodb.max_pool_size

# Max buffered finding upserts before a forced bulk flush (bounds worker memory).
# Time-based flushing is throttled by CONFIG.runners.backend_update_frequency.
MONGODB_FLUSH_SIZE = 1000

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


def update_finding(self, item):
	"""Buffer a finding upsert; the write is batched (see flush_findings).

	Findings used to be written one-by-one (one update_one/insert_one per item),
	which is millions of round-trips on a large crawl. We now mint the Mongo _id
	client-side (ObjectId() needs no round-trip) so the item has a stable id
	immediately, buffer an upsert, and flush in bulk on a size cap, on_interval
	(throttled by backend_update_frequency) and on_end.
	"""
	if type(item) not in OUTPUT_TYPES:
		return item
	if not ObjectId.is_valid(str(item._uuid)):
		item._uuid = str(ObjectId())
	buffer = getattr(self, '_mongodb_findings_buffer', None)
	if buffer is None:
		buffer = self._mongodb_findings_buffer = []
	buffer.append(
		pymongo.UpdateOne({'_id': ObjectId(item._uuid)}, {'$set': item.toDict()}, upsert=True)
	)
	if len(buffer) >= MONGODB_FLUSH_SIZE:
		flush_findings_buffer(self)
	return item


def flush_findings_buffer(self):
	"""Write all buffered finding upserts to MongoDB in a single bulk_write."""
	buffer = getattr(self, '_mongodb_findings_buffer', None)
	if not buffer:
		return
	start_time = time.time()
	client = get_mongodb_client()
	db = client.main
	count = len(buffer)
	db.findings.bulk_write(buffer, ordered=False)
	self._mongodb_findings_buffer = []
	self._last_findings_flush = start_time
	debug(f'flushed {count} findings in {time.time() - start_time:.4f}s', sub='hooks.mongodb', obj_after=False)


def flush_findings(self):
	"""on_interval hook: flush buffered findings, throttled by backend_update_frequency."""
	if should_update(CONFIG.runners.backend_update_frequency, getattr(self, '_last_findings_flush', None)):
		flush_findings_buffer(self)


def flush_findings_final(self):
	"""on_end hook: always flush remaining findings.

	This is required for correctness, not just throughput: the next runner in a
	scan re-hydrates these findings from the DB (get_results), so they must be
	persisted before this runner finishes.
	"""
	flush_findings_buffer(self)


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
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner, flush_findings],
		'on_duplicate': [update_finding],
		'on_end': [update_runner, flush_findings_final],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner, flush_findings],
		'on_duplicate': [update_finding],
		'on_end': [update_runner, flush_findings_final],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner, flush_findings],
		'on_end': [update_runner, flush_findings_final]
	}
}
