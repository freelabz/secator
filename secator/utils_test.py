import contextlib
import json
import os
import unittest.mock

from fp.fp import FreeProxy

from secator.definitions import (CIDR_RANGE, DEBUG, DELAY, DEPTH, EMAIL,
							   FOLLOW_REDIRECT, HEADER, HOST, IP, MATCH_CODES,
							   METHOD, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, URL, USER_AGENT, USERNAME)
from secator.cli import ALL_WORKFLOWS, ALL_TASKS, ALL_SCANS
from secator.output_types import OutputType
from secator.rich import console
from secator.utils import load_fixture

#---------#
# GLOBALS #
#---------#
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/tests/'
FIXTURES_DIR = f'{TEST_DIR}/fixtures'
USE_PROXY = bool(int(os.environ.get('USE_PROXY', '0')))

#------------#
# TEST TASKS #
#------------#
TEST_TASKS = os.environ.get('TEST_TASKS', '')
if TEST_TASKS:
	TEST_TASKS = [cls for cls in ALL_TASKS if cls.__name__ in TEST_TASKS.split(',')]
else:
	TEST_TASKS = ALL_TASKS

#----------------#
# TEST WORKFLOWS #
#----------------#
TEST_WORKFLOWS = os.environ.get('TEST_WORKFLOWS', '')
if TEST_WORKFLOWS:
	TEST_WORKFLOWS = [config for config in ALL_WORKFLOWS if config.name in TEST_WORKFLOWS.split(',')]
else:
	TEST_WORKFLOWS = ALL_WORKFLOWS

#------------#
# TEST SCANS #
#------------#
TEST_SCANS = os.environ.get('TEST_SCANS', '')
if TEST_SCANS:
	TEST_SCANS = [config for config in ALL_SCANS if config.name in TEST_SCANS.split(',')]
else:
	TEST_SCANS = ALL_SCANS

#-------------#
# TEST INPUTS_TASKS #
#-------------#
INPUTS_TASKS = {
	URL: 'https://fake.com',
	HOST: 'fake.com',
	USERNAME: 'test',
	IP: '192.168.1.23',
	CIDR_RANGE: '192.168.1.0/24',
	EMAIL: 'fake@fake.com'
}

#---------------------#
# TEST FIXTURES_TASKS #
#---------------------#
FIXTURES_TASKS = {
	tool_cls: load_fixture(f'{tool_cls.__name__}_output', FIXTURES_DIR)
	for tool_cls in TEST_TASKS
}

#-----------#
# TEST OPTS #
#-----------#
META_OPTS = {
	HEADER: 'User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',
	DELAY: 0,
	DEPTH: 2,
	FOLLOW_REDIRECT: True,
	METHOD: 'GET',
	MATCH_CODES: '200',
	PROXY: FreeProxy(timeout=0.5).get() if USE_PROXY else False,
	RATE_LIMIT: 10000,
	RETRIES: 0,
	THREADS: 50,
	TIMEOUT: 1,
	USER_AGENT: 'Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',

	# Individual tasks options
	'gf.pattern': 'xss',
	'nmap.output_path': load_fixture('nmap_output', FIXTURES_DIR, only_path=True, ext='.xml'),  # nmap XML fixture
	'msfconsole.resource': load_fixture('msfconsole_input', FIXTURES_DIR, only_path=True),
	'dirsearch.output_path': load_fixture('dirsearch_output', FIXTURES_DIR, only_path=True),
	'maigret.output_path': load_fixture('maigret_output', FIXTURES_DIR, only_path=True),
	'wpscan.output_path': load_fixture('wpscan_output', FIXTURES_DIR, only_path=True),
	'h8mail.output_path': load_fixture('h8mail_output', FIXTURES_DIR, only_path=True),
	'h8mail.local_breach': load_fixture('h8mail_breach', FIXTURES_DIR, only_path=True)
}


def mock_subprocess_popen(output_list):
	mock_process = unittest.mock.MagicMock()
	mock_process.wait.return_value = 0
	mock_process.stdout.readline.side_effect = output_list
	mock_process.returncode = 0

	def mock_popen(*args, **kwargs):
		return mock_process

	return unittest.mock.patch('subprocess.Popen', mock_popen)


@contextlib.contextmanager
def mock_command(cls, targets=[], opts={}, fixture=None, method=''):
	mocks = []
	if isinstance(fixture, dict):
		fixture = [fixture]

	is_list = isinstance(fixture, list)
	if is_list:
		for item in fixture:
			if isinstance(item, dict):
				mocks.append(json.dumps(item))
			else:
				mocks.append(item)
	else:
		mocks.append(fixture)

	with mock_subprocess_popen(mocks):
		command = cls(targets, **opts)
		if method == 'run':
			yield cls(targets, **opts).run()
		elif method == 'si':
			yield cls.si([], targets, **opts)
		elif method in ['s', 'delay']:
			yield getattr(cls, method)(targets, **opts)
		else:
			yield command


class CommandOutputTester:  # Mixin for unittest.TestCase

	def _test_task_output(
			self,
			results,
			expected_output_keys=[],
			expected_output_types=[],
			expected_results=[],
			empty_results_allowed=False):

		if not isinstance(results, list):
			results = [results]

		try:
			if not empty_results_allowed:
				self.assertGreater(len(results), 0)

			for item in results:

				if DEBUG > 2:
					console.log('\n', log_locals=True)

				if DEBUG > 0 and isinstance(item, OutputType):
					print(repr(item))

				if expected_output_types:
					self.assertIn(type(item), expected_output_types)

				if expected_output_keys:
					keys = [k for k in list(item.keys()) if not k.startswith('_')]
					self.assertEqual(
						set(keys).difference(set(expected_output_keys)),
						set())

			if expected_results:
				for result in expected_results:
					self.assertIn(result, results)

		except Exception:
			console.print('[bold red] failed[/]')
			raise

		console.print('[bold green] ok[/]')
