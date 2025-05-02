import contextlib
import json
import os
import sys
import unittest.mock

from fp.fp import FreeProxy

from secator.definitions import (CIDR_RANGE, DELAY, DEPTH, EMAIL,
							   FOLLOW_REDIRECT, HEADER, HOST, IP, MATCH_CODES,
							   METHOD, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, URL, USER_AGENT, USERNAME, PATH,
							   DOCKER_IMAGE, GIT_REPOSITORY)
from secator.cli import ALL_WORKFLOWS, ALL_TASKS, ALL_SCANS
from secator.output_types import EXECUTION_TYPES, STAT_TYPES
from secator.runners import Command
from secator.rich import console
from secator.utils import load_fixture, debug

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

#-------------------#
# TEST INPUTS_TASKS #
#-------------------#
INPUTS_TASKS = {
	URL: 'https://fake.com',
	HOST: 'fake.com',
	USERNAME: 'test',
	IP: '192.168.1.23',
	CIDR_RANGE: '192.168.1.0/24',
	EMAIL: 'fake@fake.com',
	PATH: '.',
	DOCKER_IMAGE: 'redis:latest',
	GIT_REPOSITORY: 'https://github.com/freelabz/secator',
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
	'bup.mode': 'http_methods',
	'gf.pattern': 'xss',
	'nmap.output_path': load_fixture('nmap_output', FIXTURES_DIR, only_path=True, ext='.xml'),  # nmap XML fixture
	'nmap.tcp_connect': True,
	'nmap.version_detection': True,
	'nmap.skip_host_discovery': True,
	'msfconsole.resource': load_fixture('msfconsole_input', FIXTURES_DIR, only_path=True),
	'dirsearch.output_path': load_fixture('dirsearch_output', FIXTURES_DIR, only_path=True),
	'gitleaks_output_path': load_fixture('gitleaks_output', FIXTURES_DIR, only_path=True),
	'maigret.output_path': load_fixture('maigret_output', FIXTURES_DIR, only_path=True),
	'nuclei.template_id': 'prometheus-metrics',
	'wpscan.output_path': load_fixture('wpscan_output', FIXTURES_DIR, only_path=True),
	'h8mail.output_path': load_fixture('h8mail_output', FIXTURES_DIR, only_path=True),
	'h8mail.local_breach': load_fixture('h8mail_breach', FIXTURES_DIR, only_path=True),
	'wpprobe.output_path': load_fixture('wpprobe_output', FIXTURES_DIR, only_path=True),
	'arjun.output_path': load_fixture('arjun_output', FIXTURES_DIR, only_path=True),
	'arjun.wordlist': False,
	'trivy.output_path': load_fixture('trivy_output', FIXTURES_DIR, only_path=True),
	'wafw00f.output_path': load_fixture('wafw00f_output', FIXTURES_DIR, only_path=True),
	'testssl.output_path': load_fixture('testssl_output', FIXTURES_DIR, only_path=True),
}


def mock_subprocess_popen(output_list):
	mock_process = unittest.mock.MagicMock()
	mock_process.wait.return_value = 0
	mock_process.stdout.readline.side_effect = output_list
	mock_process.pid = None
	mock_process.returncode = 0

	def mock_popen(*args, **kwargs):
		return mock_process

	return unittest.mock.patch('subprocess.Popen', mock_popen)


@contextlib.contextmanager
def mock_command(cls, inputs=[], opts={}, fixture=None, method=''):
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
		command = cls(inputs, **opts)
		if method == 'run':
			yield cls(inputs, **opts).run()
		elif method == 'si':
			yield cls.si([], inputs, **opts)
		elif method in ['s', 'delay']:
			yield getattr(cls, method)(inputs, **opts)
		else:
			yield command


class CommandOutputTester:  # Mixin for unittest.TestCase

	def _test_runner_output(
			self,
			runner,
			expected_output_keys=[],
			expected_output_types=[],
			expected_results=[],
			expected_status='SUCCESS',
			empty_results_allowed=False):

		console.print(f'\t[dim]Testing {runner.config.type} {runner.name} ...[/]', end='')
		debug('', sub='unittest')

		if not runner.inputs:
			console.print('[dim gold3] skipped (no inputs defined).[/]')
			return

		if not expected_results and not expected_output_keys and not expected_output_types:
			console.print('[dim gold3] (no outputs defined).[/]', end='')

		try:
			debug(f'{runner.name} starting command: {runner.cmd}', sub='unittest') if isinstance(runner, Command) else None

			# Run runner
			results = runner.run()
			for result in results:
				debug(result.toDict(), sub='unittest')

			# Add execution types to allowed output types
			expected_output_types.extend(EXECUTION_TYPES + STAT_TYPES)

			# Check return code
			if isinstance(runner, Command):
				if not runner.ignore_return_code:
					debug(f'{runner.name} should have a 0 return code', sub='unittest')
					self.assertEqual(runner.return_code, 0, f'{runner.name} should have a 0 return code. Runner return code: {runner.return_code}')  # noqa: E501

			# Check results not empty
			if not empty_results_allowed:
				debug(f'{runner.name} should return at least 1 result', sub='unittest')
				self.assertGreater(len(results), 0, f'{runner.name} should return at least 1 result')

			# Check status
			debug(f'{runner.name} should have the status {expected_status}.', sub='unittest')
			self.assertEqual(runner.status, expected_status, f'{runner.name} should have the status {expected_status}. Errors: {runner.errors}')  # noqa: E501

			# Check results
			for item in results:
				debug(f'{runner.name} yielded {repr(item)}', sub='unittest')
				debug(f'{runner.name} yielded (JSON): {json.dumps(item.toDict(), default=str)}', sub='unittest.dict', verbose=True)

				if expected_output_types:
					debug(f'{runner.name} item should have an output type in {[_._type for _ in expected_output_types]}', sub='unittest')  # noqa: E501
					self.assertIn(type(item), expected_output_types, f'{runner.name}: item has an unexpected output type "{type(item)}"')  # noqa: E501

				if expected_output_keys:
					keys = [k for k in list(item.keys()) if not k.startswith('_')]
					debug(f'{runner.name} item should have output keys {keys}', sub='unittest')
					self.assertEqual(
						set(keys).difference(set(expected_output_keys)),
						set(),
						f'{runner.name}: item is missing expected keys {set(expected_output_keys)}. Item keys: {keys}')  # noqa: E501

			# Check if runner results in expected results
			if expected_results:
				for result in expected_results:
					debug(f'{runner.name} item should be in expected results {result}.', sub='unittest')
					self.assertIn(result, results, f'{runner.name}: {result} should be in runner results.')  # noqa: E501

		except Exception:
			console.print('[dim red] failed[/]')
			raise

		console.print('[dim green] ok[/]')


def clear_modules():
	"""Clear all secator modules imports.
	See https://stackoverflow.com/questions/7460363/re-import-module-under-test-to-lose-context for context.
	"""
	keys_to_delete = []
	for k, _ in sys.modules.items():
		if k.startswith('secator'):
			keys_to_delete.append(k)
	for k in keys_to_delete:
		del sys.modules[k]
