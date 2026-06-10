from time import sleep

from secator.config import CONFIG
from secator.output_types import Error, State
from secator.utils import debug


class MongoDBPoller(object):
	"""Utility to simplify tracking a MongoDB-stored runner and its results."""

	@staticmethod
	def iter_results(
			runner_type,
			runner_id,
			refresh_interval=CONFIG.runners.poll_frequency,
			print_remote_info=True):
		"""Generator to poll results from a MongoDB runner.

		Args:
			runner_type (str): Type of runner (scan/workflow/task).
			runner_id (str): MongoDB ObjectId string.
			refresh_interval (float): Seconds between polls.
			print_remote_info (bool): Whether to show progress (reserved for future Rich UI).

		Yields:
			OutputType: Results from the runner.
		"""
		try:
			from bson.objectid import ObjectId
			from secator.hooks.mongodb import get_mongodb_client, load_findings
		except ImportError as e:
			debug(f'MongoDB imports failed: {e}', sub='mongodb.poll')
			return

		client = get_mongodb_client()
		db = client.main
		collection = f'{runner_type}s'
		seen_uuids = set()

		while True:
			# Get runner document
			try:
				runner = db[collection].find_one({'_id': ObjectId(runner_id)})
			except Exception as e:
				error = Error.from_exception(e)
				debug(repr(error), sub='mongodb.poll')
				break

			if runner is None:
				debug(f'Runner {runner_id} not found in MongoDB', sub='mongodb.poll')
				break

			done = runner.get('done', False)
			state = 'SUCCESS' if done else 'RUNNING'

			# Yield runner state
			yield State(task_id=runner_id, state=state, _source='mongodb')

			# Query all findings for this runner
			try:
				cursor = db.findings.find({f'_context.{runner_type}_id': runner_id})
				findings = load_findings(list(cursor))
			except Exception as e:
				error = Error.from_exception(e)
				debug(repr(error), sub='mongodb.poll')
				findings = []

			# Yield only new findings
			for finding in findings:
				if finding._uuid not in seen_uuids:
					seen_uuids.add(finding._uuid)
					yield finding

			if done:
				break

			sleep(refresh_interval)

	@staticmethod
	def get_results(runner_type, runner_id):
		"""Get all results from a MongoDB runner (one-shot fetch).

		Args:
			runner_type (str): Type of runner (scan/workflow/task).
			runner_id (str): MongoDB ObjectId string.

		Returns:
			list: List of OutputType instances.
		"""
		try:
			from bson.objectid import ObjectId
			from secator.hooks.mongodb import get_mongodb_client, load_findings
		except ImportError as e:
			debug(f'MongoDB imports failed: {e}', sub='mongodb.poll')
			return []

		client = get_mongodb_client()
		db = client.main
		collection = f'{runner_type}s'

		runner = db[collection].find_one({'_id': ObjectId(runner_id)})
		if not runner:
			debug(f'Runner {runner_id} not found in MongoDB', sub='mongodb.poll')
			return []

		results = list(db.findings.find({f'_context.{runner_type}_id': runner_id}))
		debug(f'Found {len(results)} results for runner {runner_id}', sub='mongodb.poll')
		return load_findings(results)
