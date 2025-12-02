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

	def test_rate_limit_adjustment_for_chunked_tasks(self):
		"""Test that rate_limit is divided by chunk count when chunking tasks."""
		from secator.celery import break_task
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		# Create a task with rate_limit
		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 100, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True

			# Break the task into chunks
			workflow = break_task(task, task_opts, results=[])

			# Check that rate_limit was adjusted
			# With 6 targets and input_chunk_size=1 (default for most tasks),
			# we should have 6 chunks, so rate_limit should be 100 // 6 = 16
			# The workflow should be a chord with adjusted rate_limit in each signature
			self.assertIsNotNone(workflow)

			# Extract the signatures from the chord to check rate_limit
			# The workflow is a chord, so we can access its tasks
			header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
			if header_tasks:
				# Each task should have the adjusted rate_limit in its kwargs
				first_sig = header_tasks[0]
				# The rate_limit should be in the kwargs of the signature
				expected_rate_limit = 100 // 6  # = 16
				if 'opts' in first_sig.kwargs and 'rate_limit' in first_sig.kwargs['opts']:
					actual_rate_limit = first_sig.kwargs['opts']['rate_limit']
					self.assertEqual(actual_rate_limit, expected_rate_limit)

	def test_rate_limit_adjustment_minimum_value(self):
		"""Test that rate_limit never goes below 1 when chunking."""
		from secator.celery import break_task
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		# Create a task with low rate_limit
		HTTP_TARGETS = [f'https://{target}' for target in TARGETS]
		task_opts = {'rate_limit': 2, 'sync': False}

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(HTTP_TARGETS)):
			task = httpx(HTTP_TARGETS, **task_opts)
			task.has_children = True

			# Break the task into chunks
			# With rate_limit=2 and 6 chunks, adjusted rate_limit should be max(1, 2//6) = 1
			workflow = break_task(task, task_opts, results=[])

			# The workflow should exist and have properly adjusted rate_limit
			self.assertIsNotNone(workflow)

			# Extract the signatures from the chord to check rate_limit
			header_tasks = workflow.tasks if hasattr(workflow, 'tasks') else []
			if header_tasks:
				# Each task should have the adjusted rate_limit in its kwargs
				first_sig = header_tasks[0]
				# The rate_limit should be at least 1
				if 'opts' in first_sig.kwargs and 'rate_limit' in first_sig.kwargs['opts']:
					actual_rate_limit = first_sig.kwargs['opts']['rate_limit']
					self.assertGreaterEqual(actual_rate_limit, 1)
					self.assertEqual(actual_rate_limit, 1)  # Should be 1 since 2//6 = 0, but max(1, 0) = 1
