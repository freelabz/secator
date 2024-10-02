import logging
import time

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
MAX_POOL_SIZE = 100

logger = logging.getLogger(__name__)

client = pymongo.MongoClient(escape_mongodb_url(MONGODB_URL), maxPoolSize=MAX_POOL_SIZE)


def update_runner(self):
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	update = self.toDict()
	debug_obj = {'type': 'runner', 'name': self.name, 'status': self.status}
	chunk = update.get('chunk')
	_id = self.context.get(f'{type}_chunk_id') if chunk else self.context.get(f'{type}_id')
	debug('update', sub='hooks.mongodb', id=_id, obj=update, obj_after=True, level=4)
	start_time = time.time()
	if _id:
		delta = start_time - self.last_updated if self.last_updated else MONGODB_UPDATE_FREQUENCY
		if self.last_updated and delta < MONGODB_UPDATE_FREQUENCY and self.status == 'RUNNING':
			debug(f'skipped ({delta:>.2f}s < {MONGODB_UPDATE_FREQUENCY}s)',
				  sub='hooks.mongodb', id=_id, obj=debug_obj, obj_after=False, level=3)
			return
		db = client.main
		start_time = time.time()
		db[collection].update_one({'_id': ObjectId(_id)}, {'$set': update})
		end_time = time.time()
		elapsed = end_time - start_time
		debug(
			f'[dim gold4]updated in {elapsed:.4f}s[/]', sub='hooks.mongodb', id=_id, obj=debug_obj, obj_after=False, level=2)
		self.last_updated = start_time
	else:  # sync update and save result to runner object
		runner = db[collection].insert_one(update)
		_id = str(runner.inserted_id)
		if chunk:
			self.context[f'{type}_chunk_id'] = _id
		else:
			self.context[f'{type}_id'] = _id
		end_time = time.time()
		elapsed = end_time - start_time
		debug(f'created in {elapsed:.4f}s', sub='hooks.mongodb', id=_id, obj=debug_obj, obj_after=False, level=2)


def update_finding(self, item):
	start_time = time.time()
	db = client.main
	update = item.toDict()
	_id = ObjectId(item._uuid) if ObjectId.is_valid(item._uuid) else None
	if _id:
		finding = db['findings'].update_one({'_id': _id}, {'$set': update})
		status = 'UPDATED'
	else:
		finding = db['findings'].insert_one(update)
		item._uuid = str(finding.inserted_id)
		status = 'CREATED'
	end_time = time.time()
	elapsed = end_time - start_time
	debug(f'in {elapsed:.4f}s', sub='hooks.mongodb', id=str(item._uuid), obj={'finding': status}, obj_after=False)
	return item


def find_duplicates(self):
	ws_id = self.toDict().get('context', {}).get('workspace_id')
	if not ws_id:
		return
	celery_id = tag_duplicates.delay(ws_id)
	debug(f'running duplicate check on workspace {ws_id}', id=celery_id, sub='hooks.mongodb')


def load_finding(obj):
	finding_type = obj['_type']
	klass = None
	for otype in OUTPUT_TYPES:
		if finding_type == otype.get_name():
			klass = otype
			item = klass.load(obj)
			item._uuid = str(obj['_id'])
			return item
	debug('could not load Secator output type from MongoDB object', obj=obj, sub='hooks.mongodb')
	return None


def load_findings(objs):
	findings = [load_finding(obj) for obj in objs]
	return [f for f in findings if f is not None]


@shared_task
def tag_duplicates(ws_id: str = None):
	"""Tag duplicates in workspace.

	Args:
		ws_id (str): Workspace id.
	"""
	db = client.main
	workspace_query = list(
		db.findings.find({'_context.workspace_id': str(ws_id), '_tagged': True}).sort('_timestamp', -1))
	untagged_query = list(
		db.findings.find({'_context.workspace_id': str(ws_id)}).sort('_timestamp', -1))
	# TODO: use this instead when duplicate removal logic is final
	# untagged_query = list(
	# 	db.findings.find({'_context.workspace_id': str(ws_id), '_tagged': False}).sort('_timestamp', -1))
	if not untagged_query:
		debug('no untagged findings. Skipping.', id=ws_id, sub='hooks.mongodb')
		return

	untagged_findings = load_findings(untagged_query)
	workspace_findings = load_findings(workspace_query)
	non_duplicates = []
	duplicates = []
	for item in untagged_findings:
		# If already seen in duplicates
		seen = [f for f in duplicates if f._uuid == item._uuid]
		if seen:
			continue

		# Check for duplicates
		tmp_duplicates = []

		# Check if already present in list of workspace_findings findings, list of duplicates, or untagged_findings
		workspace_dupes = [f for f in workspace_findings if f == item and f._uuid != item._uuid]
		untagged_dupes = [f for f in untagged_findings if f == item and f._uuid != item._uuid]
		seen_dupes = [f for f in duplicates if f == item and f._uuid != item._uuid]
		tmp_duplicates.extend(workspace_dupes)
		tmp_duplicates.extend(untagged_dupes)
		tmp_duplicates.extend(seen_dupes)
		debug(
			f'for item {item._uuid}',
			obj={
				'workspace dupes': len(workspace_dupes),
				'untagged dupes': len(untagged_dupes),
				'seen dupes': len(seen_dupes)
			},
			id=ws_id,
			sub='hooks.mongodb')
		tmp_duplicates_ids = list(dict.fromkeys([i._uuid for i in tmp_duplicates]))
		debug(f'duplicate ids: {tmp_duplicates_ids}', id=ws_id, sub='hooks.mongodb')

		# Update latest object as non-duplicate
		if tmp_duplicates:
			duplicates.extend([f for f in tmp_duplicates])
			db.findings.update_one({'_id': ObjectId(item._uuid)}, {'$set': {'_related': tmp_duplicates_ids}})
			debug(f'adding {item._uuid} as non-duplicate', id=ws_id, sub='hooks.mongodb')
			non_duplicates.append(item)
		else:
			debug(f'adding {item._uuid} as non-duplicate', id=ws_id, sub='hooks.mongodb')
			non_duplicates.append(item)

	# debug(f'found {len(duplicates)} total duplicates')

	# Update objects with _tagged and _duplicate fields
	duplicates_ids = list(dict.fromkeys([n._uuid for n in duplicates]))
	non_duplicates_ids = list(dict.fromkeys([n._uuid for n in non_duplicates]))

	search = {'_id': {'$in': [ObjectId(d) for d in duplicates_ids]}}
	update = {'$set': {'_context.workspace_duplicate': True, '_tagged': True}}
	db.findings.update_many(search, update)

	search = {'_id': {'$in': [ObjectId(d) for d in non_duplicates_ids]}}
	update = {'$set': {'_context.workspace_duplicate': False, '_tagged': True}}
	db.findings.update_many(search, update)
	debug(
		'completed duplicates check for workspace.',
		id=ws_id,
		obj={
			'processed': len(untagged_findings),
			'duplicates': len(duplicates_ids),
			'non-duplicates': len(non_duplicates_ids)
		},
		sub='hooks.mongodb')


MONGODB_HOOKS = {
	Scan: {
		'on_start': [update_runner],
		'on_iter': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_start': [update_runner],
		'on_iter': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_iter': [update_runner],
		'on_end': [update_runner, find_duplicates]
	}
}
