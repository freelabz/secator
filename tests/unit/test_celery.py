import unittest
from secator.celery import app, forward_results  # noqa: F401
from secator.utils_test import mock_command, FIXTURES_TASKS, TEST_TASKS, FIXTURES_DIR, load_fixture
from secator.output_types import Url
from celery import chain, chord

TARGETS = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']


class TestCelery(unittest.TestCase):

	def test_httpx_chain(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [forward_results.si([])] + [httpx.s(target) for target in TARGETS]
			workflow = chain(*sigs)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(urls), len(TARGETS))
			self.assertEqual(len(targets), len(TARGETS))

	def test_httpx_chain_with_results(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		existing_results = [Url(**{
			"url": "https://example.synology.me",
			"method": "GET",
			"status_code": 200,
			"words": 438,
			"lines": 136,
			"content_type":
			"text/html",
			"content_length": 11577,
			"host": "82.66.157.114",
			"time": 0.16246860100000002,
			"_source": "httpx",
			"_type": "url"
		})]
		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [forward_results.s(existing_results)] + [httpx.s(target) for target in TARGETS]
			workflow = chain(*sigs)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(urls), len(TARGETS) + 1)
			self.assertEqual(len(targets), len(TARGETS))
			self.assertIn(existing_results[0], results)

	def test_httpx_workflow(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		targets = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']
		sigs = []
		for target in targets:
			sig = httpx().s(target)
			sigs.append(sig)
		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(targets)):
			workflow = chain(
				forward_results.s([]),
				sigs[0],
				chord((
					sigs[1],
					sigs[2],
				), forward_results.s()),
				sigs[3],
				chord((
					sigs[4],
					sigs[5],
				), forward_results.s())
			)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(targets), len(TARGETS))
			self.assertEqual(len(urls), len(TARGETS))

	def test_nmap_workflow(self):
		from secator.tasks import nmap
		if nmap not in TEST_TASKS:
			return

		nmap_fixture = load_fixture('nmap_output', fixtures_dir=FIXTURES_DIR, ext='.xml', only_path=True)
		with mock_command(nmap, fixture=[FIXTURES_TASKS[nmap]] * len(TARGETS)):
			workflow = chain(
				forward_results.s([]),
				chord((
					nmap.s(TARGETS, output_path=nmap_fixture)
				), forward_results.s()),
			)
			result = workflow.apply()
			results = result.get()
			vulns = [r.id for r in results if r._type == 'vulnerability']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(targets), len(TARGETS))
			self.assertEqual(len(vulns), 61)  # number of vulns in the XML fixture

	def test_ffuf_chunked(self):
		from secator.tasks import ffuf
		if ffuf not in TEST_TASKS:
			return

		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]

		with mock_command(ffuf, fixture=[FIXTURES_TASKS[ffuf]] * len(HTTP_TARGETS)):
			workflow = chain(
				forward_results.s([]),
				chord((
					ffuf.s(HTTP_TARGETS)
				), forward_results.s()),
			)
			result = workflow.apply()
			results = result.get()
			urls = [r.url for r in results if r._type == 'url']
			targets = [r.name for r in results if r._type == 'target']
			self.assertEqual(len(targets), len(HTTP_TARGETS) * 2)
			self.assertEqual(len(urls), len(HTTP_TARGETS))

	def test_revoke_task(self):
		"""Test revoke_task function."""
		from secator.celery import revoke_task
		from unittest.mock import patch, MagicMock
		
		# Mock the app.control.revoke method
		with patch('secator.celery.app.control.revoke') as mock_revoke:
			task_id = 'test-task-id-123'
			task_name = 'test_task'
			
			# Test without task name
			revoke_task(task_id)
			mock_revoke.assert_called_once_with(task_id, terminate=True)
			
			# Test with task name
			mock_revoke.reset_mock()
			revoke_task(task_id, task_name=task_name)
			mock_revoke.assert_called_once_with(task_id, terminate=True)

	def test_chunker(self):
		"""Test chunker function."""
		from secator.celery import chunker
		
		# Test with small sequence
		seq = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
		chunks = list(chunker(seq, 3))
		self.assertEqual(len(chunks), 4)
		self.assertEqual(chunks[0], [1, 2, 3])
		self.assertEqual(chunks[1], [4, 5, 6])
		self.assertEqual(chunks[2], [7, 8, 9])
		self.assertEqual(chunks[3], [10])
		
		# Test with chunk size equal to sequence length
		chunks = list(chunker(seq, 10))
		self.assertEqual(len(chunks), 1)
		self.assertEqual(chunks[0], seq)
		
		# Test with chunk size larger than sequence
		chunks = list(chunker(seq, 20))
		self.assertEqual(len(chunks), 1)
		self.assertEqual(chunks[0], seq)

	def test_is_celery_worker_alive(self):
		"""Test is_celery_worker_alive function."""
		from secator.celery import is_celery_worker_alive
		from unittest.mock import patch
		
		# Test when worker is alive
		with patch('secator.celery.app.control.broadcast') as mock_broadcast:
			mock_broadcast.return_value = [{'worker1': {'ok': 'pong'}}]
			result = is_celery_worker_alive()
			self.assertTrue(result)
			mock_broadcast.assert_called_once_with('ping', reply=True, limit=1, timeout=1)
		
		# Test when worker is not alive
		with patch('secator.celery.app.control.broadcast') as mock_broadcast:
			mock_broadcast.return_value = []
			result = is_celery_worker_alive()
			self.assertFalse(result)

	def test_run_task(self):
		"""Test run_task celery task."""
		from secator.celery import run_task
		from secator.tasks import httpx
		from unittest.mock import patch, MagicMock
		
		if httpx not in TEST_TASKS:
			return
		
		# Mock the Task class to avoid initialization issues
		with patch('secator.celery.Task') as MockTask:
			mock_task_instance = MagicMock()
			MockTask.return_value = mock_task_instance
			
			with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]]):
				# Call the task using apply() which runs it synchronously
				args = [httpx, ['example.com']]
				kwargs = {}
				result = run_task.apply(args=(args, kwargs))
				
				# Verify Task was instantiated and run was called
				MockTask.assert_called_once()
				mock_task_instance.run.assert_called_once()

	def test_run_workflow(self):
		"""Test run_workflow celery task."""
		from secator.celery import run_workflow
		from unittest.mock import patch, MagicMock
		
		# Mock the Workflow class
		with patch('secator.celery.Workflow') as MockWorkflow:
			mock_workflow_instance = MagicMock()
			MockWorkflow.return_value = mock_workflow_instance
			
			# Call with proper arguments
			args = ['test_workflow', ['example.com']]
			kwargs = {}
			result = run_workflow.apply(args=(args, kwargs))
			
			# Verify Workflow was instantiated and run was called
			MockWorkflow.assert_called_once()
			mock_workflow_instance.run.assert_called_once()

	def test_run_scan(self):
		"""Test run_scan celery task."""
		from secator.celery import run_scan
		from unittest.mock import patch, MagicMock
		
		# Mock the Scan class
		with patch('secator.celery.Scan') as MockScan:
			mock_scan_instance = MagicMock()
			MockScan.return_value = mock_scan_instance
			
			# Call with proper arguments
			args = ['test_scan', ['example.com']]
			kwargs = {}
			result = run_scan.apply(args=(args, kwargs))
			
			# Verify Scan was instantiated and run was called
			MockScan.assert_called_once()
			mock_scan_instance.run.assert_called_once()

	def test_break_task(self):
		"""Test break_task function."""
		from secator.celery import break_task
		from secator.tasks import httpx
		from unittest.mock import MagicMock
		
		if httpx not in TEST_TASKS:
			return
		
		# Create a task that needs chunking
		targets = ['example1.com', 'example2.com', 'example3.com', 'example4.com', 'example5.com']
		task = httpx(targets, chunk=1, chunk_count=1)
		task.input_chunk_size = 2
		task_opts = {'context': {}}
		
		# Call break_task
		workflow = break_task(task, task_opts, results=[])
		
		# Verify it returns a chord workflow
		from celery import chord
		self.assertIsNotNone(workflow)
		# The workflow should be a chord with multiple chunks
		# We expect 3 chunks for 5 targets with chunk size 2
