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


class TestTaskQueueRouting(unittest.TestCase):
	"""resolve_task_queue: static profiles are overridable, dynamic profiles always win."""

	def setUp(self):
		from secator.config import CONFIG
		self._saved = dict(CONFIG.tasks.overrides) if CONFIG.tasks.overrides else {}

	def tearDown(self):
		from secator.config import CONFIG
		# Mutate in place rather than reassigning, so the DotMap-backed Config field keeps its type
		# (a plain dict would break CONFIG.set()'s auto-vivification of nested keys for later tests).
		CONFIG.tasks.overrides.clear()
		CONFIG.tasks.overrides.update(self._saved)

	def test_static_profile_default(self):
		from secator.runners._helpers import resolve_task_queue
		from secator.tasks import nmap
		self.assertEqual(resolve_task_queue(nmap, {}), 'small')

	def test_static_profile_override_applies(self):
		from secator.config import CONFIG
		from secator.runners._helpers import resolve_task_queue
		from secator.tasks import nmap
		CONFIG.tasks.overrides['nmap'] = {'profile': 'small_long'}
		self.assertEqual(resolve_task_queue(nmap, {}), 'small_long')

	def test_dynamic_profile_ignores_override(self):
		"""A callable profile (katana) must not be flattened by an env override."""
		from secator.config import CONFIG
		from secator.runners._helpers import resolve_task_queue
		from secator.tasks import katana
		CONFIG.tasks.overrides['katana'] = {'profile': 'small_long'}
		# headless vs non-headless still resolve via dynamic_profile, never to the override.
		self.assertNotEqual(resolve_task_queue(katana, {'headless': True}), 'small_long')
		self.assertEqual(resolve_task_queue(katana, {}), 'medium')


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


class TestNmapTruncatedXml(unittest.TestCase):
	"""nmap may produce truncated XML (missing </nmaprun>) when killed, e.g. on task timeout."""

	def _parse(self, content):
		from secator.output_types import Error, Port
		from secator.tasks.nmap import nmap
		fixtures_dir = os.path.join(os.path.dirname(__file__), '..', 'fixtures')
		path = os.path.join(fixtures_dir, '_nmap_truncated_test.xml')
		with open(path, 'w') as f:
			f.write(content)
		try:
			task = nmap.__new__(nmap)
			task.output_path = path
			results = list(task.xml_to_json())
		finally:
			os.remove(path)
		errors = [r for r in results if isinstance(r, Error)]
		ports = [r for r in results if isinstance(r, Port)]
		return errors, ports

	def _load_full_fixture(self):
		path = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'nmap_output.xml')
		with open(path) as f:
			return f.read()

	def test_full_xml_parses(self):
		"""A complete XML output parses without errors and yields ports."""
		errors, ports = self._parse(self._load_full_fixture())
		self.assertEqual(errors, [])
		self.assertTrue(len(ports) > 0)

	def test_truncated_xml_is_repaired(self):
		"""XML truncated before </nmaprun> (host complete) is repaired and still yields ports."""
		full = self._load_full_fixture()
		truncated = full.split('</host>')[0] + '</host>\n'  # complete host but no runstats/</nmaprun>
		errors, ports = self._parse(truncated)
		self.assertEqual(errors, [])
		self.assertTrue(len(ports) > 0)

	def test_truncated_xml_no_host_does_not_error(self):
		"""XML truncated mid-scan (no completed host) is repaired and parses without errors."""
		truncated = (
			'<?xml version="1.0" encoding="UTF-8"?>\n'
			'<!DOCTYPE nmaprun>\n'
			'<nmaprun scanner="nmap" args="nmap -p - secator.cloud" start="1781863253" version="7.98">\n'
			'<scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>\n'
			'<verbose level="0"/>\n'
			'<taskprogress task="Connect Scan" time="1781863273" percent="12.10" remaining="139" etc="1781863411"/>\n'
		)
		errors, ports = self._parse(truncated)
		self.assertEqual(errors, [])


class TestMaxTimeout(unittest.TestCase):
	"""Per-task max_timeout resolution (class attribute, config override, global fallback)."""

	def test_default_falls_back_to_global(self):
		"""max_timeout=None resolves to CONFIG.celery.task_max_timeout."""
		from secator.tasks.nmap import nmap
		task = nmap.__new__(nmap)
		self.assertIsNone(task.max_timeout)  # default class attribute
		with unittest.mock.patch('secator.runners.command.CONFIG') as mock_config:
			mock_config.celery.task_max_timeout = 42
			self.assertEqual(task.get_max_timeout(), 42)

	def test_per_task_value_takes_precedence(self):
		"""A per-task max_timeout overrides the global default."""
		from secator.tasks.nmap import nmap
		task = nmap.__new__(nmap)
		task.max_timeout = 100
		with unittest.mock.patch('secator.runners.command.CONFIG') as mock_config:
			mock_config.celery.task_max_timeout = 42
			self.assertEqual(task.get_max_timeout(), 100)

	def test_disabled_timeout_resolves_to_minus_one(self):
		"""A per-task max_timeout of -1 (no timeout) is honored over a global limit."""
		from secator.tasks.nmap import nmap
		task = nmap.__new__(nmap)
		task.max_timeout = -1
		with unittest.mock.patch('secator.runners.command.CONFIG') as mock_config:
			mock_config.celery.task_max_timeout = 42
			self.assertEqual(task.get_max_timeout(), -1)

	def test_config_override_sets_instance_attribute(self):
		"""`tasks.overrides.<task>.max_timeout` is parsed as int and applied as an attribute."""
		from secator.config import CONFIG
		CONFIG.set('tasks.overrides.nmap.max_timeout', '100')
		override = CONFIG.tasks.overrides.get('nmap', {})
		self.assertEqual(override.get('max_timeout'), 100)
		self.assertIsInstance(override.get('max_timeout'), int)


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

		cve_count = len(next(iter(fixture.values())).get('vulns', {}))
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

		cve_count = len(next(iter(fixture.values())).get('vulns', {}))
		self.assertEqual(len(vulns), cve_count * 2)
		matched_ats = {v.matched_at for v in vulns}
		self.assertEqual(matched_ats, {'10.0.0.1:80', '10.0.0.2:80'})
