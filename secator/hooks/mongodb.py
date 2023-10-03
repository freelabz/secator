from bson.objectid import ObjectId
import os
import logging
import time

from celery import shared_task

from secator.rich import console
from secator.definitions import DEBUG
from secator.runners import Task, Workflow, Scan

import pymongo
import gevent.monkey
gevent.monkey.patch_all()

MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb://localhost')
UPDATE_FREQUENCY_SECONDS = 10
client = pymongo.MongoClient(MONGODB_URL)

logger = logging.getLogger(__name__)


def update_runner(self):
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	existing_id = self.context.get(f'{type}_id')
	update = self.toDict()
	start_time = time.time()
	delta = start_time - self.last_updated
	if existing_id:
		if delta < UPDATE_FREQUENCY_SECONDS and self.status == 'RUNNING':
			# console.log(f'mongodb: skipping update for performance ({delta}s < {UPDATE_FREQUENCY_SECONDS}s)')
			return
		self.last_updated = start_time
		update_runner_lazy.apply(args=(collection, existing_id, update), queue='db')
	else:  # sync update and save result to runner object
		runner = db[collection].insert_one(update)
		self.context[f'{type}_id'] = str(runner.inserted_id)
		if DEBUG > 0:
			end_time = time.time()
			elapsed_time = end_time - start_time
			console.log(f'mongodb: Created {type} {runner.inserted_id} in {elapsed_time:.4f}s', style='dim yellow')


def save_finding(self, item):
	save_finding_lazy.apply(args=(item.toDict(),), queue='db')
	return item


@shared_task
def save_finding_lazy(item):
	start_time = time.time()
	db = client.main
	finding = db['findings'].insert_one(item)
	end_time = time.time()
	elapsed_time = end_time - start_time
	if DEBUG > 0:
		console.log(f'mongodb: Created finding {finding.inserted_id} in {elapsed_time:.4f}s', style='dim yellow')


@shared_task
def update_runner_lazy(collection, id, update):
	db = client.main
	start_time = time.time()
	db[collection].update_one({'_id': ObjectId(id)}, {'$set': update})
	status = update['status']
	end_time = time.time()
	elapsed_time = end_time - start_time
	if DEBUG > 0:
		console.log(f'mongodb: Updated {collection} {id} in {elapsed_time:.4f}s with status {status}', style='dim yellow')


MONGODB_HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_iter': [update_runner],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_iter': [update_runner],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_item': [save_finding],
		'on_iter': [update_runner],
		'on_end': [update_runner]
	}
}
