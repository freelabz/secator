import unittest
from unittest import mock
from bson.objectid import ObjectId

from secator.hooks.mongodb import (
	get_mongodb_client,
	get_runner_dbg,
	get_results,
	update_runner,
	update_finding,
	find_duplicates,
	load_finding,
	load_findings,
	tag_duplicates
)


class TestMongoDBClient(unittest.TestCase):
	"""Test MongoDB client creation and management"""

	def setUp(self):
		"""Reset global MongoDB client before each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	def tearDown(self):
		"""Reset global MongoDB client after each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	@mock.patch('secator.hooks.mongodb.pymongo.MongoClient')
	def test_get_mongodb_client_creates_client(self, mock_mongo_client):
		"""Test that get_mongodb_client creates a MongoDB client with correct parameters"""
		# Call get_mongodb_client
		client = get_mongodb_client()

		# Verify MongoClient was called
		self.assertTrue(mock_mongo_client.called)
		self.assertIsNotNone(client)

	@mock.patch('secator.hooks.mongodb.pymongo.MongoClient')
	def test_get_mongodb_client_singleton(self, mock_mongo_client):
		"""Test that get_mongodb_client returns the same client on subsequent calls"""
		# Get client twice
		client1 = get_mongodb_client()
		client2 = get_mongodb_client()

		# Verify MongoClient was only called once
		self.assertEqual(mock_mongo_client.call_count, 1)
		self.assertIs(client1, client2)


class TestRunnerDebug(unittest.TestCase):
	"""Test runner debug helper function"""

	def test_get_runner_dbg(self):
		"""Test that get_runner_dbg returns correct debug information"""
		# Create a mock runner
		mock_runner = mock.Mock()
		mock_runner.unique_name = 'test_runner'
		mock_runner.status = 'running'
		mock_runner.config.type = 'task'
		mock_runner.config.name = 'test_task'
		mock_runner.__class__.__name__ = 'Task'
		mock_runner.context = {'workspace_id': '123', 'scan_id': '456'}

		# Get debug info
		debug_info = get_runner_dbg(mock_runner)

		# Verify structure
		self.assertEqual(debug_info['test_runner'], 'running')
		self.assertEqual(debug_info['type'], 'task')
		self.assertEqual(debug_info['class'], 'Task')
		self.assertEqual(debug_info['caller'], 'test_task')
		self.assertEqual(debug_info['workspace_id'], '123')
		self.assertEqual(debug_info['scan_id'], '456')


class TestGetResults(unittest.TestCase):
	"""Test get_results function"""

	def setUp(self):
		"""Reset global MongoDB client before each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	def tearDown(self):
		"""Reset global MongoDB client after each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	def test_get_results_with_valid_uuids(self, mock_get_client):
		"""Test get_results with valid ObjectId UUIDs"""
		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.Mock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Create test data
		test_id = ObjectId()
		mock_finding = {
			'_id': test_id,
			'_type': 'url',
			'url': 'https://example.com'
		}
		mock_db.findings.find.return_value = [mock_finding]

		# Call get_results
		results = list(get_results([str(test_id)]))

		# Verify
		mock_db.findings.find.assert_called_once()
		self.assertEqual(len(results), 1)

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	def test_get_results_with_output_types(self, mock_get_client):
		"""Test get_results with mixed output types and UUIDs"""
		from secator.output_types import Url

		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.Mock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client
		mock_db.findings.find.return_value = []

		# Create a mock output object
		mock_output = Url(url='https://example.com')

		# Call get_results with mixed types
		results = list(get_results([mock_output]))

		# Verify output objects are yielded directly
		self.assertEqual(len(results), 1)
		self.assertIs(results[0], mock_output)

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	def test_get_results_with_invalid_uuids(self, mock_get_client):
		"""Test get_results with invalid UUIDs"""
		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.Mock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		mock_db.findings.find.return_value = []

		# Call get_results with invalid UUID
		results = list(get_results(['invalid-uuid']))

		# Verify no results
		self.assertEqual(len(results), 0)


class TestUpdateRunner(unittest.TestCase):
	"""Test update_runner function"""

	def setUp(self):
		"""Reset global MongoDB client before each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	def tearDown(self):
		"""Reset global MongoDB client after each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	@mock.patch('secator.hooks.mongodb.get_runner_dbg')
	def test_update_runner_new_runner(self, mock_get_runner_dbg, mock_debug, mock_get_client):
		"""Test update_runner creates a new runner entry"""
		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.MagicMock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Setup mock runner
		mock_runner = mock.Mock()
		mock_runner.config.type = 'task'
		mock_runner.config.name = 'test_task'
		mock_runner.unique_name = 'test_runner'
		mock_runner.status = 'running'
		mock_runner.context = {}
		mock_runner.toDict.return_value = {'name': 'test_task', 'status': 'running'}

		# Setup mock insert response
		mock_insert_result = mock.Mock()
		mock_insert_result.inserted_id = ObjectId()
		mock_db.__getitem__.return_value.insert_one.return_value = mock_insert_result

		# Call update_runner
		update_runner(mock_runner)

		# Verify insert was called
		mock_db.__getitem__.assert_called_with('tasks')
		self.assertIn('task_id', mock_runner.context)

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	@mock.patch('secator.hooks.mongodb.get_runner_dbg')
	def test_update_runner_existing_runner(self, mock_get_runner_dbg, mock_debug, mock_get_client):
		"""Test update_runner updates an existing runner entry"""
		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.MagicMock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Setup mock runner with existing ID
		existing_id = str(ObjectId())
		mock_runner = mock.Mock()
		mock_runner.config.type = 'task'
		mock_runner.config.name = 'test_task'
		mock_runner.unique_name = 'test_runner'
		mock_runner.status = 'running'
		mock_runner.context = {'task_id': existing_id}
		mock_runner.toDict.return_value = {'name': 'test_task', 'status': 'running'}

		# Setup mock collection
		mock_collection = mock.Mock()
		mock_db.__getitem__.return_value = mock_collection

		# Call update_runner
		update_runner(mock_runner)

		# Verify update was called
		mock_db.__getitem__.assert_called_with('tasks')
		mock_collection.update_one.assert_called_once()
		self.assertTrue(hasattr(mock_runner, 'last_updated_db'))


class TestUpdateFinding(unittest.TestCase):
	"""Test update_finding function"""

	def setUp(self):
		"""Reset global MongoDB client before each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	def tearDown(self):
		"""Reset global MongoDB client after each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	def test_update_finding_new_item(self, mock_debug, mock_get_client):
		"""Test update_finding creates a new finding"""
		from secator.output_types import Url

		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.MagicMock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Setup mock runner
		mock_runner = mock.Mock()
		mock_runner.config.name = 'test_task'
		mock_runner.context = {}
		mock_runner.__class__.__name__ = 'Task'

		# Create test item
		test_item = Url(url='https://example.com')
		test_item._uuid = 'new-item'

		# Setup mock insert response
		mock_insert_result = mock.Mock()
		mock_insert_result.inserted_id = ObjectId()
		mock_db.__getitem__.return_value.insert_one.return_value = mock_insert_result

		# Call update_finding
		result = update_finding(mock_runner, test_item)

		# Verify
		mock_db.__getitem__.assert_called_with('findings')
		self.assertIsNotNone(result._uuid)

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	def test_update_finding_existing_item(self, mock_debug, mock_get_client):
		"""Test update_finding updates an existing finding"""
		from secator.output_types import Url

		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.MagicMock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Setup mock runner
		mock_runner = mock.Mock()
		mock_runner.config.name = 'test_task'
		mock_runner.context = {}
		mock_runner.__class__.__name__ = 'Task'

		# Create test item with valid ObjectId
		test_item = Url(url='https://example.com')
		test_item._uuid = str(ObjectId())

		# Setup mock collection
		mock_collection = mock.Mock()
		mock_db.__getitem__.return_value = mock_collection

		# Call update_finding
		result = update_finding(mock_runner, test_item)

		# Verify
		mock_db.__getitem__.assert_called_with('findings')
		mock_collection.update_one.assert_called_once()
		self.assertEqual(result, test_item)

	def test_update_finding_non_output_type(self):
		"""Test update_finding returns non-output items unchanged"""
		# Setup mock runner
		mock_runner = mock.Mock()

		# Call with non-output type
		result = update_finding(mock_runner, "not an output type")

		# Verify it's returned unchanged
		self.assertEqual(result, "not an output type")


class TestFindDuplicates(unittest.TestCase):
	"""Test find_duplicates function"""

	@mock.patch('secator.hooks.mongodb.tag_duplicates')
	def test_find_duplicates_without_workspace(self, mock_tag_duplicates):
		"""Test find_duplicates does nothing without workspace_id"""
		# Setup mock runner without workspace_id
		mock_runner = mock.Mock()
		mock_runner.toDict.return_value = {'context': {}}

		# Call find_duplicates
		find_duplicates(mock_runner)

		# Verify tag_duplicates was not called
		mock_tag_duplicates.assert_not_called()

	@mock.patch('secator.hooks.mongodb.tag_duplicates')
	@mock.patch('secator.celery.IN_CELERY_WORKER_PROCESS', False)
	def test_find_duplicates_with_workspace(self, mock_tag_duplicates):
		"""Test find_duplicates calls tag_duplicates with workspace_id"""
		# Setup mock runner with workspace_id
		mock_runner = mock.Mock()
		mock_runner.toDict.return_value = {'context': {'workspace_id': 'ws123'}}

		# Call find_duplicates
		find_duplicates(mock_runner)

		# Verify tag_duplicates was called
		mock_tag_duplicates.assert_called_once_with('ws123')

	@mock.patch('secator.celery.IN_CELERY_WORKER_PROCESS', True)
	def test_find_duplicates_in_celery_worker(self):
		"""Test find_duplicates uses Celery task when in worker process"""
		from unittest.mock import patch

		# Setup mock runner with workspace_id
		mock_runner = mock.Mock()
		mock_runner.toDict.return_value = {'context': {'workspace_id': 'ws123'}}

		# Mock the tag_duplicates.delay method
		with patch('secator.hooks.mongodb.tag_duplicates') as mock_tag_dup:
			mock_delay = mock.Mock()
			mock_tag_dup.delay = mock_delay

			# Call find_duplicates
			find_duplicates(mock_runner)

			# Verify delay was called
			mock_delay.assert_called_once_with('ws123')


class TestLoadFinding(unittest.TestCase):
	"""Test load_finding and load_findings functions"""

	def test_load_finding_url(self):
		"""Test load_finding with URL type"""
		# Create mock finding object
		test_id = ObjectId()
		finding_obj = {
			'_id': test_id,
			'_type': 'url',
			'url': 'https://example.com',
			'status_code': 200
		}

		# Load finding
		result = load_finding(finding_obj)

		# Verify
		self.assertIsNotNone(result)
		self.assertEqual(result._type, 'url')
		self.assertEqual(result._uuid, str(test_id))
		self.assertEqual(result.url, 'https://example.com')

	def test_load_finding_unknown_type(self):
		"""Test load_finding with unknown type returns None"""
		finding_obj = {
			'_id': ObjectId(),
			'_type': 'unknown_type'
		}

		# Load finding
		result = load_finding(finding_obj)

		# Verify
		self.assertIsNone(result)

	def test_load_finding_with_exclude_types(self):
		"""Test load_finding with excluded types"""
		finding_obj = {
			'_id': ObjectId(),
			'_type': 'url',
			'url': 'https://example.com'
		}

		# Load finding with excluded type
		result = load_finding(finding_obj, exclude_types=['url'])

		# Verify
		self.assertIsNone(result)

	def test_load_findings_multiple(self):
		"""Test load_findings with multiple findings"""
		test_id1 = ObjectId()
		test_id2 = ObjectId()

		findings = [
			{'_id': test_id1, '_type': 'url', 'url': 'https://example.com'},
			{'_id': test_id2, '_type': 'url', 'url': 'https://test.com'},
			{'_id': ObjectId(), '_type': 'unknown_type'}
		]

		# Load findings
		results = load_findings(findings)

		# Verify - should return 2 valid findings, filtering out unknown type
		self.assertEqual(len(results), 2)
		self.assertEqual(results[0]._uuid, str(test_id1))
		self.assertEqual(results[1]._uuid, str(test_id2))


class TestTagDuplicates(unittest.TestCase):
	"""Test tag_duplicates Celery task"""

	def setUp(self):
		"""Reset global MongoDB client before each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	def tearDown(self):
		"""Reset global MongoDB client after each test"""
		import secator.hooks.mongodb as mongodb_module
		mongodb_module._mongodb_client = None

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	@mock.patch('secator.hooks.mongodb.load_findings')
	def test_tag_duplicates_no_updates(self, mock_load_findings, mock_debug, mock_get_client):
		"""Test tag_duplicates with no duplicates found"""
		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.Mock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Setup mock queries
		mock_db.findings.find.return_value.sort.return_value = []
		mock_load_findings.return_value = []

		# Call tag_duplicates
		tag_duplicates('ws123')

		# Verify no bulk_write was called
		mock_db.findings.bulk_write.assert_not_called()

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	@mock.patch('secator.hooks.mongodb.load_findings')
	def test_tag_duplicates_with_duplicates(self, mock_load_findings, mock_debug, mock_get_client):
		"""Test tag_duplicates with duplicates found"""
		from secator.output_types import Url

		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.Mock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Create mock findings - two identical URLs
		url1 = Url(url='https://example.com')
		url1._uuid = str(ObjectId())
		url1._timestamp = 1000
		url1._related = []

		url2 = Url(url='https://example.com')
		url2._uuid = str(ObjectId())
		url2._timestamp = 2000
		url2._related = []

		# Mock load_findings - first call returns workspace findings, second returns untagged
		mock_load_findings.side_effect = [[], [url1, url2]]

		# Setup mock queries
		mock_db.findings.find.return_value.sort.return_value = []

		# Setup mock bulk write result
		mock_bulk_result = mock.Mock()
		mock_db.findings.bulk_write.return_value = mock_bulk_result

		# Call tag_duplicates
		tag_duplicates('ws123')

		# Verify bulk_write was called (duplicates were found)
		mock_db.findings.bulk_write.assert_called_once()

	@mock.patch('secator.hooks.mongodb.get_mongodb_client')
	@mock.patch('secator.hooks.mongodb.debug')
	@mock.patch('secator.hooks.mongodb.load_findings')
	def test_tag_duplicates_full_scan(self, mock_load_findings, mock_debug, mock_get_client):
		"""Test tag_duplicates with full_scan=True"""
		# Setup mock MongoDB client
		mock_client = mock.Mock()
		mock_db = mock.Mock()
		mock_client.main = mock_db
		mock_get_client.return_value = mock_client

		# Setup mock queries
		mock_db.findings.find.return_value.sort.return_value = []
		mock_load_findings.return_value = []

		# Call tag_duplicates with full_scan
		tag_duplicates('ws123', full_scan=True)

		# Verify the query was made (checking that function executed)
		self.assertTrue(mock_db.findings.find.called)


if __name__ == '__main__':
	unittest.main()
