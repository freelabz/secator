import json
import logging
import os
import unittest
import unittest.mock
import warnings

from secator.definitions import DEBUG
from secator.output_types import Vulnerability
from secator.rich import console
from secator.tasks.search_vulns import search_vulns
from secator.utils import setup_logging
from secator.utils_test import (FIXTURES_TASKS, INPUTS_TASKS, META_OPTS,
							  CommandOutputTester, mock_command)

level = logging.DEBUG if DEBUG == ["1"] else logging.ERROR
setup_logging(level)


class TestTasks(unittest.TestCase, CommandOutputTester):

	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

	def _valid_fixture(self, cls, fixture):
		if not fixture:
			if len(FIXTURES_TASKS.keys()) == 1 and hasattr(cls, 'cmd'): # make test fail.
				raise AssertionError(f'No fixture for {cls.__name__}! Add one to the tests/fixtures directory (must not be an empty file / empty json / empty list).')
			return False
		return True

	def test_cmd_converted_schema(self):
		console.print('')

		from secator.config import CONFIG
		if 'debug_command' in CONFIG.debug:
			META_OPTS['print_cmd'] = True
			META_OPTS['print_item'] = True

		failures = []
		for cls, fixture in FIXTURES_TASKS.items():
			with self.subTest(name=cls.__name__):
				# Validate fixture
				if not self._valid_fixture(cls, fixture):
					console.print(f'\tTesting task {cls.__name__} ... [dim gold3] skipped (no fixture)[/]')
					continue

				# Run command
				input_type = cls.input_types[0] if cls.input_types else 'fake'
				targets = INPUTS_TASKS.get(cls.__name__)
				if not targets:
					targets = INPUTS_TASKS.get(input_type, [])
				with mock_command(cls, targets, META_OPTS, fixture) as runner:
					try:
						self._test_runner_output(
							runner,
							expected_output_types=cls.output_types
						)
					except Exception as e:
						failures.append(f'ERROR ({cls.__name__}): {e}')

		if failures:
			raise AssertionError("\n\n" + "\n\n".join(failures))


class TestSearchVulnsGrouping(unittest.TestCase):

	def _load_fixture(self):
		fixture_path = os.path.join(
			os.path.dirname(__file__), '..', 'fixtures', 'search_vulns_output.json'
		)
		with open(fixture_path) as f:
			return json.load(f)

	def test_before_init_single_host(self):
		"""before_init parses single host from matched_at~service format."""
		task = search_vulns.__new__(search_vulns)
		task.inputs = ['10.0.0.1:80~apache 2.4.39']
		task.matched_at = None
		search_vulns.before_init(task)
		self.assertEqual(task.matched_at, '10.0.0.1:80')
		self.assertEqual(task.inputs[0], 'apache 2.4.39')

	def test_before_init_no_tilde_leaves_inputs_unchanged(self):
		"""before_init with no tilde leaves inputs and matched_at unchanged."""
		task = search_vulns.__new__(search_vulns)
		task.inputs = ['apache 2.4.39']
		task.matched_at = None
		search_vulns.before_init(task)
		self.assertIsNone(task.matched_at)
		self.assertEqual(task.inputs[0], 'apache 2.4.39')

	def test_before_init_multiple_hosts(self):
		"""before_init correctly captures comma-separated matched_at hosts."""
		task = search_vulns.__new__(search_vulns)
		task.inputs = ['10.0.0.1:80,10.0.0.2:80~apache 2.4.39']
		task.matched_at = None
		search_vulns.before_init(task)
		self.assertEqual(task.matched_at, '10.0.0.1:80,10.0.0.2:80')
		self.assertEqual(task.inputs[0], 'apache 2.4.39')

	def test_on_json_loaded_single_host_emits_one_vuln(self):
		"""on_json_loaded with single matched_at emits one Vulnerability per CVE."""
		fixture = self._load_fixture()
		task = search_vulns.__new__(search_vulns)
		task.inputs = ['apache 2.4.39']
		task.matched_at = '10.0.0.1:80'
		task.run_opts = {}

		vulns = []
		for data in fixture.items():
			item = dict([data])
			for result in search_vulns.on_json_loaded(task, item):
				if isinstance(result, Vulnerability):
					vulns.append(result)
			break  # one fixture entry is enough

		cve_count = len(list(fixture.values())[0].get('vulns', {}))
		self.assertEqual(len(vulns), cve_count)
		for v in vulns:
			self.assertEqual(v.matched_at, '10.0.0.1:80')

	def test_on_json_loaded_multiple_hosts_emits_vuln_per_host(self):
		"""on_json_loaded with comma-separated matched_at emits one Vulnerability per host per CVE."""
		fixture = self._load_fixture()
		task = search_vulns.__new__(search_vulns)
		task.inputs = ['apache 2.4.39']
		task.matched_at = '10.0.0.1:80,10.0.0.2:80'
		task.run_opts = {}

		vulns = []
		for data in fixture.items():
			item = dict([data])
			for result in search_vulns.on_json_loaded(task, item):
				if isinstance(result, Vulnerability):
					vulns.append(result)
			break

		cve_count = len(list(fixture.values())[0].get('vulns', {}))
		self.assertEqual(len(vulns), cve_count * 2)
		matched_ats = {v.matched_at for v in vulns}
		self.assertEqual(matched_ats, {'10.0.0.1:80', '10.0.0.2:80'})
