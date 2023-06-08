from pymongo import MongoClient
from bson.objectid import ObjectId
import os

MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb://localhost')


def update_runner(self):
	client = MongoClient(MONGODB_URL)
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	existing_id = self.context.get(f'{type}_id')
	update = self.toDict()
	if existing_id:
		db[collection].update_one({'_id': ObjectId(existing_id)}, {'$set': update})
		print(f'updated {type} {existing_id}')
	else:
		runner = db[collection].insert_one(update)
		self.context[f'{type}_id'] = str(runner.inserted_id)
		print(f'created {type} {runner.inserted_id}')


def save_finding(self, item):
	client = MongoClient(MONGODB_URL)
	db = client.main
	finding = db['findings'].insert_one(item.toDict())
	item._uuid = str(finding.inserted_id)
	print(f'created finding {finding.inserted_id}')
	return item
