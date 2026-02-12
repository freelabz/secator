

class MongoDBPoller(object):
	"""Utility to simplify tracking a MongoDB task and all of its subtasks."""

	def iter_results(self, runner_type, runner_id):
		"""Generator to get results from MongoDB task.

		Args:
			runner_type (str): Type of runner.
			runner_id (str): ID of the runner.

		Yields:
			dict: Subtasks state and results.
		"""
		results = MongoDBPoller.get_results(runner_type, runner_id)
		yield from results

	@staticmethod
	def get_results(runner_type, runner_id):
		"""Get results from MongoDB task.

		Args:
			runner_type (str): Type of runner.
			runner_id (str): ID of the runner.

		Returns:
			list: List of results.
		"""
		from secator.hooks.mongodb import get_mongodb_client, load_findings
		from bson.objectid import ObjectId
		client = get_mongodb_client()
		db = client.main
		runner = db.runners.find_one({
			'type': runner_type,
			'_id': ObjectId(runner_id)
		})
		print(runner.toDict())
		if not runner:
			return []
		results = db.findings.find({
			'_context.{runner_type}_id': runner_id
		})
		print('Found results:', len(list(results)))
		return load_findings(list(results))
