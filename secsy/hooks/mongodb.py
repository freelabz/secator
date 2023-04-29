from pymongo import MongoClient
from bson.objectid import ObjectId


def save_scan(self):
	client = MongoClient('mongodb://localhost')
	db = client.main
	scan = db['scans'].insert_one(self.toDict())
	self.context['scan_id'] = str(scan.inserted_id)


def update_scan(self):
	client = MongoClient('mongodb://localhost')
	db = client.main
	scan_id = self.context['scan_id']
	db['scans'].update_one({'_id': ObjectId(scan_id)}, {'$set': self.toDict()})


def save_workflow(self):
	client = MongoClient('mongodb://localhost')
	db = client.main
	workflow = db['workflows'].insert_one(self.toDict())
	self.context['workflow_id'] = str(workflow.inserted_id)


def update_workflow(self):
	client = MongoClient('mongodb://localhost')
	db = client.main
	workflow_id = self.context['workflow_id']
	db['workflows'].update_one({'_id': ObjectId(workflow_id)}, {'$set': self.toDict()})


def save_task(self):
	client = MongoClient('mongodb://localhost')
	db = client.main
	task = db['tasks'].insert_one(self.toDict())
	self.context['task_id'] = str(task.inserted_id)


def save_finding(self, item):
	client = MongoClient('mongodb://localhost')
	db = client.main
	finding = db['findings'].insert_one(item.toDict())
	item._uuid = str(finding.inserted_id)
	return item


def update_task(self):
	client = MongoClient('mongodb://localhost')
	db = client.main
	task_id = self.context['task_id']
	db['tasks'].update_one({'_id': ObjectId(task_id)}, {'$set': self.toDict()})