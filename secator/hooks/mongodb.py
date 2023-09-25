from bson.objectid import ObjectId
import os
import logging
import time

from secator.definitions import DEBUG
from secator.runners import Task, Workflow, Scan

import pymongo
# import gevent.monkey
# gevent.monkey.patch_all()

MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb://localhost')
UPDATE_FREQUENCY_SECONDS = int(os.environ.get('MONGODB_UPDATE_FREQUENCY', 10))
MAX_POOL_SIZE = 100
client = pymongo.MongoClient(MONGODB_URL, maxPoolSize=MAX_POOL_SIZE)

logger = logging.getLogger(__name__)


def update_runner(self):
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	existing_id = self.context.get(f'{type}_id')
	update = self.toDict()
	start_time = time.time()
	if existing_id:
		delta = start_time - self.last_updated if self.last_updated else UPDATE_FREQUENCY_SECONDS
		if self.last_updated and delta < UPDATE_FREQUENCY_SECONDS and self.status == 'RUNNING':
			if DEBUG > 1:
				self._print(
					f'[dim red]\[debug][/] [dim yellow]hooks.mongodb: {type[0]} {self.name} {existing_id} -> '
					f'{self.status}[/] [dim purple]skipped ({delta:>.2f}s < {UPDATE_FREQUENCY_SECONDS}s)[/]', markup=True)
			return
		db = client.main
		start_time = time.time()
		db[collection].update_one({'_id': ObjectId(existing_id)}, {'$set': update})
		end_time = time.time()
		elapsed_time = end_time - start_time
		if DEBUG > 0:
			self._print(
				f'[dim red]\[debug][/] [dim yellow]hooks.mongodb: {type[0]} {self.name} {existing_id} -> '
				f'{self.status}[/] [dim green]updated in {elapsed_time:.4f}s[/]', markup=True)
		self.last_updated = start_time
	else:  # sync update and save result to runner object
		runner = db[collection].insert_one(update)
		self.context[f'{type}_id'] = str(runner.inserted_id)
		if DEBUG > 0:
			end_time = time.time()
			elapsed_time = end_time - start_time
			self._print(
				f'[dim red]\[debug][/] [dim yellow]hooks.mongodb: {type[0]} {self.name} {runner.inserted_id} -> '
				f'{self.status}[/] [dim green]created in {elapsed_time:.4f}s[/]', markup=True)


def save_finding(self, item):
	start_time = time.time()
	db = client.main
	finding = db['findings'].insert_one(item.toDict())
	item._uid = str(finding.inserted_id)
	end_time = time.time()
	elapsed_time = end_time - start_time
	if DEBUG > 0:
		self._print(
			f'[dim red]\[debug][/] [dim yellow]hooks.mongodb: f {finding.inserted_id}[/] [dim green]created in '
			f'{elapsed_time:.4f}s[/]', markup=True)
	return item


MONGODB_HOOKS = {
	Scan: {
		'on_start': [update_runner],
		'on_iter': [update_runner],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_start': [update_runner],
		'on_iter': [update_runner],
		'on_end': [update_runner],
	},
	Task: {
		'on_start': [update_runner],
		'on_item': [save_finding],
		'on_iter': [update_runner],
		'on_end': [update_runner]
	}
}
