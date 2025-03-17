import queue
import os
import unittest
import warnings

from time import sleep
from threading import Thread

from celery import chain, chord

from secator.celery import app, forward_results
from secator.config import CONFIG
from secator.utils_test import TEST_TASKS, TEST_WORKFLOWS,load_fixture
from secator.runners import Command
from secator.output_types import Url
from tests.integration.inputs import INPUTS_SCANS


INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
OPTS = {
	'ffuf.filter_size': '3748,3106',
	'ffuf.depth': 1,
	'ffuf.follow_redirect': True,
	'ffuf.wordlist': load_fixture('wordlist', INTEGRATION_DIR, only_path=True),
}
URL_TARGETS = INPUTS_SCANS['url']
URL_RESULTS_COUNT = [14, 1]
TAG_RESULTS_COUNT = []
HOST_TARGETS = INPUTS_SCANS['host']


class TestCelery(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		Command.execute(
			f'sh {INTEGRATION_DIR}/setup.sh',
			quiet=True,
			cwd=INTEGRATION_DIR
		)
		cls.queue = queue.Queue()
		cls.cmd = Command.execute('secator worker', quiet=True, run=False)
		cls.thread = Thread(target=cls.cmd.run)
		cls.thread.start()
		sleep(5)

	@classmethod
	def tearDownClass(cls) -> None:
		cls.cmd.stop_process()
		cls.thread.join()
		Command.execute(
			f'sh {INTEGRATION_DIR}/teardown.sh',
			quiet=True,
			cwd=INTEGRATION_DIR
		)

	def test_httpx_chain(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return
		sigs = [forward_results.si([])] + [httpx.s(target) for target in URL_TARGETS]
		workflow = chain(*sigs)
		result = workflow.apply()
		results = result.get()
		urls = [r.url for r in results if r._type == 'url']
		targets = [r.name for r in results if r._type == 'target']
		self.assertEqual(len(urls), len(URL_TARGETS))
		self.assertEqual(len(targets), len(URL_TARGETS))

	def test_httpx_chain_prior_results(self):
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
		targets = INPUTS_SCANS['url']
		sigs = [forward_results.s(existing_results)] + [httpx.s(target) for target in URL_TARGETS]
		workflow = chain(*sigs)
		result = workflow.apply()
		results = result.get()
		urls = [r.url for r in results if r._type == 'url']
		targets = [r.name for r in results if r._type == 'target']
		self.assertEqual(len(urls), len(URL_TARGETS) + 1)
		self.assertEqual(len(targets), len(URL_TARGETS))
		self.assertIn(existing_results[0], results)

	def test_httpx_chord(self):
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

		sigs = []
		for target in URL_TARGETS:
			sig = httpx().s(target)
			sigs.append(sig)
		workflow = chain(
			forward_results.s(existing_results),
			sigs[0],
			chord((
				sigs[1],
				sigs[0],
			), forward_results.s()),
			sigs[1],
			chord((
				sigs[0],
				sigs[1],
			), forward_results.s())
		)
		result = workflow.apply()
		results = result.get()
		urls = [r.url for r in results if r._type == 'url']
		targets = [r.name for r in results if r._type == 'target']
		self.assertIn(existing_results[0], results)
		self.assertEqual(len(targets), len(targets))
		self.assertEqual(len(urls), len(targets) + 1)

	def test_httpx_chunk(self):
		from secator.tasks import httpx
		if httpx not in TEST_TASKS:
			return

		size = CONFIG.runners.input_chunk_size + 1
		targets = [URL_TARGETS[0]] * size
		result = httpx.delay(targets)
		results = result.get()
		urls = [r.url for r in results if r._type == 'url']
		infos = [r.message for r in results if r._type == 'info']
		self.assertEqual(len(urls), 2)  # same URL, but twice because 2 chunks and same input
		# self.assertEqual(len(infos), 2) # one chunk message for each chunk
		# for message in infos:
			# self.assertIn('Celery chunked task created', message)

	def test_nmap_chain(self):
		from secator.tasks import nmap
		if nmap not in TEST_TASKS:
			return

		workflow = chain(
			forward_results.s([]),
			chord((
				nmap.s(URL_TARGETS)
			), forward_results.s()),
		)
		result = workflow.apply()
		results = result.get()
		targets = [r.name for r in results if r._type == 'target']
		self.assertEqual(len(targets), len(URL_TARGETS))

	def test_ffuf_chunked(self):
		from secator.tasks import ffuf
		if ffuf not in TEST_TASKS:
			return

		targets = [t + '/FUZZ' for t in URL_TARGETS]
		workflow = chain(
			forward_results.s([]),
			chord((
				ffuf.s(targets, **OPTS)
			), forward_results.s()),
		)
		result = workflow.apply()
		results = result.get()
		targets = [r.name for r in results if r._type == 'target']
		urls = [r.url for r in results if r._type == 'url']
		self.assertEqual(len(targets), len(URL_TARGETS))
		self.assertEqual(len(urls), sum(URL_RESULTS_COUNT))

	def test_url_vuln_workflow(self):
		from secator.workflows import url_vuln
		workflow = url_vuln([t + '?id=1' for t in URL_TARGETS])
		workflow = workflow.build_celery_workflow()
		result = workflow.apply()
		results = result.get()
		targets = [r.name for r in results if r._type == 'target']
		tags = [r.name for r in results if r._type == 'tag']
		self.assertEqual(len(targets), 16)
		self.assertEqual(len(tags), 6)
