"""End-to-end tests for the secator CLI.

Covers the following axes for each runner type (task / workflow / scan):

Target formats
    - Single target
    - Two targets (comma-separated)
    - File-based targets (one per line)

Exporter flags  (-o csv | json | txt | table | console | csv,json,txt)
    Note: 'markdown' is not a supported exporter name; 'table' is the
    equivalent (it uses Markdown headings).  Tests check exit code only
    because the output directory is controlled by the loaded config.

Driver flag     (--driver api)
    The API driver is tested with a mocked ``requests.request`` so that
    no real network calls are made to an external API.

    Note: 'discord' is not a supported driver; available drivers are
    mongodb, gcs, api.  MongoDB driver CLI tests require Docker and are
    covered in test_drivers.py.

Tasks tested
    - httpx  – single HTTP probe (fast, suitable for all target-format /
               exporter / driver combinations)
    - ffuf   – fuzzer, tested with a small file-based wordlist
    - host_recon workflow (passive mode)
    - host scan
"""

import os
import shutil
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from secator.cli import cli
from secator.utils_test import TEST_TASKS

TEST_URL = 'https://wikipedia.org'
TEST_URL_2 = 'https://example.com'
TEST_HOST = 'wikipedia.org'


def _mock_api_request(method, url, **kwargs):
	"""Mock ``requests.request`` that returns a minimal success response."""
	resp = MagicMock()
	resp.ok = True
	resp.status_code = 200
	resp.json.return_value = {'id': 'test-001'}
	return resp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_driver_patches():
	"""Return a list of patch context managers that prevent real API calls."""
	return [
		patch('secator.hooks.api.API_URL', 'https://mock-api.example.com'),
		patch('secator.hooks.api.API_KEY', 'test-key'),
		patch('secator.hooks.api.API_HEADER_NAME', 'Bearer'),
		patch('secator.hooks.api.API_WORKSPACE_GET_ENDPOINT', ''),
		patch('secator.hooks.api.FORCE_SSL', False),
		patch('requests.request', side_effect=_mock_api_request),
		# get_workspace_name is imported inside the CLI handler; patch the
		# module attribute so the local `from … import` picks up the mock.
		patch('secator.hooks.api.get_workspace_name', return_value='test-workspace'),
	]


# ---------------------------------------------------------------------------
# Task CLI tests
# ---------------------------------------------------------------------------

class TestCLITask(unittest.TestCase):
	"""Test task execution via the CLI across all input and output variations."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx, ffuf
		cls.skip_httpx = httpx not in TEST_TASKS
		cls.skip_ffuf = ffuf not in TEST_TASKS
		cls.runner = CliRunner()
		cls.tmpdir = tempfile.mkdtemp(prefix='secator_e2e_cli_task_')

	@classmethod
	def tearDownClass(cls):
		if hasattr(cls, 'tmpdir') and os.path.exists(cls.tmpdir):
			shutil.rmtree(cls.tmpdir, ignore_errors=True)

	def _invoke(self, args, patches=None):
		"""Invoke the CLI with *args*, optionally under a list of mock patches."""
		from contextlib import ExitStack
		with ExitStack() as stack:
			if patches:
				for p in patches:
					stack.enter_context(p)
			return self.__class__.runner.invoke(cli, args, catch_exceptions=False)

	# ------------------------------------------------------------------ #
	# Target format tests (httpx)                                          #
	# ------------------------------------------------------------------ #

	def test_single_target(self):
		"""CLI runs httpx against a single target successfully."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_two_targets_comma_separated(self):
		"""CLI runs httpx against two comma-separated targets."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', f'{TEST_URL},{TEST_URL_2}', '--sync'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_file_based_targets(self):
		"""CLI reads targets from a file (one per line) and runs httpx against each."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		targets_file = os.path.join(self.__class__.tmpdir, 'targets.txt')
		Path(targets_file).write_text(f'{TEST_URL}\n{TEST_URL_2}\n')
		result = self._invoke(['task', 'httpx', targets_file, '--sync'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	# ------------------------------------------------------------------ #
	# Exporter tests (httpx, single target)                                #
	# ------------------------------------------------------------------ #

	def test_exporter_csv(self):
		"""CLI -o csv flag is accepted and task completes without error."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync', '-o', 'csv'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_exporter_json(self):
		"""CLI -o json flag is accepted and task completes without error."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync', '-o', 'json'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_exporter_txt(self):
		"""CLI -o txt flag is accepted and task completes without error."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync', '-o', 'txt'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_exporter_console(self):
		"""CLI -o console flag is accepted and task completes without error."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync', '-o', 'console'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_exporter_table(self):
		"""CLI -o table flag is accepted and task completes without error (Markdown-equivalent)."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync', '-o', 'table'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_exporter_multiple(self):
		"""CLI -o csv,json,txt runs all three exporters in a single invocation."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(['task', 'httpx', TEST_URL, '--sync', '-o', 'csv,json,txt'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	# ------------------------------------------------------------------ #
	# Driver tests (API driver mocked)                                     #
	# ------------------------------------------------------------------ #

	def test_driver_api(self):
		"""CLI --driver api registers the API driver hooks; all HTTP calls are mocked."""
		if self.__class__.skip_httpx:
			self.skipTest('httpx not in TEST_TASKS')
		result = self._invoke(
			['task', 'httpx', TEST_URL, '--sync', '--driver', 'api'],
			patches=_api_driver_patches(),
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	# ------------------------------------------------------------------ #
	# ffuf with small wordlist                                             #
	# ------------------------------------------------------------------ #

	def test_ffuf_small_wordlist_single_target(self):
		"""CLI runs ffuf with a small file-based wordlist against a single URL."""
		if self.__class__.skip_ffuf:
			self.skipTest('ffuf not in TEST_TASKS')
		wordlist = os.path.join(self.__class__.tmpdir, 'small_wordlist.txt')
		Path(wordlist).write_text('admin\nlogin\napi\ntest\nindex\n')
		result = self._invoke(
			['task', 'ffuf', TEST_URL, '--wordlist', wordlist, '--sync']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_ffuf_small_wordlist_two_targets(self):
		"""CLI runs ffuf against two comma-separated targets with a small wordlist."""
		if self.__class__.skip_ffuf:
			self.skipTest('ffuf not in TEST_TASKS')
		wordlist = os.path.join(self.__class__.tmpdir, 'small_wordlist_2.txt')
		Path(wordlist).write_text('admin\nlogin\napi\ntest\nindex\n')
		result = self._invoke(
			['task', 'ffuf', f'{TEST_URL},{TEST_URL_2}', '--wordlist', wordlist, '--sync']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_ffuf_small_wordlist_file_targets(self):
		"""CLI runs ffuf reading targets from a file with a small wordlist."""
		if self.__class__.skip_ffuf:
			self.skipTest('ffuf not in TEST_TASKS')
		targets_file = os.path.join(self.__class__.tmpdir, 'ffuf_targets.txt')
		Path(targets_file).write_text(f'{TEST_URL}\n{TEST_URL_2}\n')
		wordlist = os.path.join(self.__class__.tmpdir, 'small_wordlist_3.txt')
		Path(wordlist).write_text('admin\nlogin\napi\ntest\nindex\n')
		result = self._invoke(
			['task', 'ffuf', targets_file, '--wordlist', wordlist, '--sync']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')


# ---------------------------------------------------------------------------
# Workflow CLI tests
# ---------------------------------------------------------------------------

class TestCLIWorkflow(unittest.TestCase):
	"""Test workflow execution via the CLI (host_recon in passive mode)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx, nmap
		cls.skip_all = httpx not in TEST_TASKS or nmap not in TEST_TASKS
		cls.runner = CliRunner()
		cls.tmpdir = tempfile.mkdtemp(prefix='secator_e2e_cli_wf_')

	@classmethod
	def tearDownClass(cls):
		if hasattr(cls, 'tmpdir') and os.path.exists(cls.tmpdir):
			shutil.rmtree(cls.tmpdir, ignore_errors=True)

	def _invoke(self, args, patches=None):
		"""Invoke the CLI with optional mock patches."""
		from contextlib import ExitStack
		with ExitStack() as stack:
			if patches:
				for p in patches:
					stack.enter_context(p)
			return self.__class__.runner.invoke(cli, args, catch_exceptions=False)

	def test_workflow_single_target(self):
		"""CLI runs host_recon workflow (passive) against a single host."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(['workflow', 'host_recon', TEST_HOST, '--sync', '--passive'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_workflow_two_targets(self):
		"""CLI runs host_recon workflow (passive) against two comma-separated hosts."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['workflow', 'host_recon', f'{TEST_HOST},example.com', '--sync', '--passive']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_workflow_file_based_targets(self):
		"""CLI runs host_recon workflow (passive) reading hosts from a file."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		targets_file = os.path.join(self.__class__.tmpdir, 'wf_hosts.txt')
		Path(targets_file).write_text(f'{TEST_HOST}\nexample.com\n')
		result = self._invoke(
			['workflow', 'host_recon', targets_file, '--sync', '--passive']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_workflow_exporters_csv_json_txt(self):
		"""CLI runs host_recon with -o csv,json,txt; all exporters accepted."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['workflow', 'host_recon', TEST_HOST, '--sync', '--passive', '-o', 'csv,json,txt']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_workflow_exporter_console(self):
		"""CLI runs host_recon with -o console; exporter is accepted."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['workflow', 'host_recon', TEST_HOST, '--sync', '--passive', '-o', 'console']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_workflow_exporter_table(self):
		"""CLI runs host_recon with -o table (Markdown-equivalent); exporter is accepted."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['workflow', 'host_recon', TEST_HOST, '--sync', '--passive', '-o', 'table']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_workflow_driver_api(self):
		"""CLI runs host_recon with --driver api; all API calls are mocked."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['workflow', 'host_recon', TEST_HOST, '--sync', '--passive', '--driver', 'api'],
			patches=_api_driver_patches(),
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')


# ---------------------------------------------------------------------------
# Scan CLI tests
# ---------------------------------------------------------------------------

class TestCLIScan(unittest.TestCase):
	"""Test scan execution via the CLI (host scan)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)
		from secator.tasks import httpx, nmap
		cls.skip_all = httpx not in TEST_TASKS or nmap not in TEST_TASKS
		cls.runner = CliRunner()
		cls.tmpdir = tempfile.mkdtemp(prefix='secator_e2e_cli_scan_')

	@classmethod
	def tearDownClass(cls):
		if hasattr(cls, 'tmpdir') and os.path.exists(cls.tmpdir):
			shutil.rmtree(cls.tmpdir, ignore_errors=True)

	def _invoke(self, args, patches=None):
		"""Invoke the CLI with optional mock patches."""
		from contextlib import ExitStack
		with ExitStack() as stack:
			if patches:
				for p in patches:
					stack.enter_context(p)
			return self.__class__.runner.invoke(cli, args, catch_exceptions=False)

	def test_scan_single_target(self):
		"""CLI runs host scan against a single target."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(['scan', 'host', TEST_HOST, '--sync'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_scan_two_targets(self):
		"""CLI runs host scan against two comma-separated targets."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(['scan', 'host', f'{TEST_HOST},example.com', '--sync'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_scan_file_based_targets(self):
		"""CLI runs host scan reading targets from a file."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		targets_file = os.path.join(self.__class__.tmpdir, 'scan_targets.txt')
		Path(targets_file).write_text(f'{TEST_HOST}\nexample.com\n')
		result = self._invoke(['scan', 'host', targets_file, '--sync'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_scan_exporters_csv_json_txt(self):
		"""CLI runs host scan with -o csv,json,txt; all exporters accepted."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['scan', 'host', TEST_HOST, '--sync', '-o', 'csv,json,txt']
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_scan_exporter_console(self):
		"""CLI runs host scan with -o console; exporter is accepted."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(['scan', 'host', TEST_HOST, '--sync', '-o', 'console'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_scan_exporter_table(self):
		"""CLI runs host scan with -o table (Markdown-equivalent); exporter is accepted."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(['scan', 'host', TEST_HOST, '--sync', '-o', 'table'])
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')

	def test_scan_driver_api(self):
		"""CLI runs host scan with --driver api; all API calls are mocked."""
		if self.__class__.skip_all:
			self.skipTest('Required tasks not in TEST_TASKS')
		result = self._invoke(
			['scan', 'host', TEST_HOST, '--sync', '--driver', 'api'],
			patches=_api_driver_patches(),
		)
		self.assertEqual(result.exit_code, 0, f'exit {result.exit_code}:\n{result.output}')


if __name__ == '__main__':
	unittest.main()
