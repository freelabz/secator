from bson.objectid import ObjectId
import os
import logging
import time

from celery import shared_task

from secator.rich import console
from secator.definitions import DEBUG

import eventlet
pymongo = eventlet.import_patched('pymongo')

MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb://localhost')
client = pymongo.MongoClient(MONGODB_URL)

logger = logging.getLogger(__name__)


def update_runner(self):
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	existing_id = self.context.get(f'{type}_id')
	update = self.toDict()
	start_time = time.time()
	if existing_id:
		update_runner_lazy.apply_async(args=(collection, existing_id, update), queue='db')
	else: # sync update and save result to runner object
		runner = db[collection].insert_one(update)
		self.context[f'{type}_id'] = str(runner.inserted_id)
		if DEBUG > 0:
			end_time = time.time()
			elapsed_time = end_time - start_time
			console.log(f'mongodb: Created {type} {runner.inserted_id} in {elapsed_time:.4f}s', style='dim yellow')


def save_finding(self, item):
	save_finding_lazy.apply_async(args=(item.toDict(),), queue='db')
	return item


@shared_task
def save_finding_lazy(item):
	from secator.hooks.mongodb import client
	import time
	start_time = time.time()
	db = client.main
	finding = db['findings'].insert_one(item)
	end_time = time.time()
	elapsed_time = end_time - start_time
	if DEBUG > 0:
		console.log(f'mongodb: Created finding {finding.inserted_id} in {elapsed_time:.4f}s', style='dim yellow')


@shared_task
def update_runner_lazy(collection, id, update):
	from secator.hooks.mongodb import client
	import time
	db = client.main
	start_time = time.time()
	db[collection].update_one({'_id': ObjectId(id)}, {'$set': update})
	end_time = time.time()
	elapsed_time = end_time - start_time
	if DEBUG > 0:
		console.log(f'mongodb: Updated {collection} {id} in {elapsed_time:.4f}s', style='dim yellow')