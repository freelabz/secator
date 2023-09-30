from bson.objectid import ObjectId
import os
import logging
import time

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
		db[collection].update_one({'_id': ObjectId(existing_id)}, {'$set': update})
		if DEBUG:
			end_time = time.time()
			elapsed_time = end_time - start_time
			console.log(f'mongodb: Updated {type} {existing_id} in {elapsed_time:.4f}s', style='dim yellow')
	else:
		runner = db[collection].insert_one(update)
		self.context[f'{type}_id'] = str(runner.inserted_id)
		if DEBUG > 0:
			end_time = time.time()
			elapsed_time = end_time - start_time
			console.log(f'mongodb: Created {type} {runner.inserted_id} in {elapsed_time:.4f}s', style='dim yellow')


def save_finding(self, item):
	from secator.celery import save_finding_to_db
	save_finding_to_db.apply_async(args=(item.toDict(),), queue='db')
	# start_time = time.time()
	# db = client.main
	# finding = db['findings'].insert_one(item.toDict())
	# item._uuid = str(finding.inserted_id)
	# if DEBUG > 0:
	# 	end_time = time.time()
	# 	elapsed_time = end_time - start_time
	# 	console.log(f'mongodb: Created finding {finding.inserted_id} in {elapsed_time:.4f}s', style='dim yellow')
	# return item