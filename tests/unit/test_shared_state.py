"""Regression tests: state that must not be shared between runners / lookup calls."""
import copy
import inspect
import unittest
from unittest import mock

from secator.decorators import cache_copy
from secator.loader import get_configs_by_type
from secator.output_types import Vulnerability
from secator.runners import Workflow
from secator.runners._base import Runner


class TestRunnerContextDefault(unittest.TestCase):

	def _workflow(self, **kwargs):
		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')
		return Workflow(workflows[0], inputs=['example.com'], run_opts={'dry_run': True}, **kwargs)

	def test_context_default_is_not_shared(self):
		w1 = self._workflow()
		w2 = self._workflow()
		self.assertIsNot(w1.context, w2.context)
		self.assertNotEqual(w1.context['workflow_id'], w2.context['workflow_id'])

	def test_context_default_is_not_mutated(self):
		self._workflow()
		self.assertIsNone(inspect.signature(Runner.__init__).parameters['context'].default)

	def test_explicit_context_is_still_updated_in_place(self):
		ctx = {}
		wf = self._workflow(context=ctx)
		self.assertIs(wf.context, ctx)
		self.assertIn('workflow_id', ctx)


class TestCacheCopy(unittest.TestCase):

	def test_callers_get_independent_copies(self):
		calls = []

		@cache_copy
		def lookup(key):
			calls.append(key)
			return Vulnerability(name=key, provider='test', tags=['base'], references=[], extra_data={})

		first = lookup('CVE-1')
		first.tags.append('exploitable')
		first.references.append('https://example.com')
		first.extra_data['x'] = 1
		second = lookup('CVE-1')
		self.assertEqual(calls, ['CVE-1'])  # still cached
		self.assertEqual(second.tags, ['base'])
		self.assertEqual(second.references, [])
		self.assertEqual(second.extra_data, {})
		self.assertIsNone(lookup('CVE-2').extra_data.get('x'))
		lookup.cache_clear()
		lookup('CVE-1')
		self.assertEqual(calls, ['CVE-1', 'CVE-2', 'CVE-1'])

	def test_vuln_lookup_cve_returns_copies(self):
		from secator.providers._base import CVEProvider
		from secator.tasks._categories import Vuln
		base = Vulnerability(
			name='CVE-2099-0001', id='CVE-2099-0001', provider='test', tags=[], references=[],
			extra_data={'cpes': ['cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*']})
		Vuln.lookup_cve.cache_clear()
		with mock.patch.object(CVEProvider, 'lookup_local_cve', return_value=None), \
			mock.patch.object(CVEProvider, 'lookup_external_cve', side_effect=lambda *a, **k: copy.deepcopy(base)):
			first = Vuln.lookup_cve('CVE-2099-0001', 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*')
			first.tags.append('exploitable')
			first.references.append('https://example.com/a')
			first.extra_data['extra'] = True
			second = Vuln.lookup_cve('CVE-2099-0001', 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*')
		Vuln.lookup_cve.cache_clear()
		self.assertIsNot(first, second)
		self.assertEqual(second.tags, ['cpe-match'])
		self.assertEqual(second.references, [])
		self.assertNotIn('extra', second.extra_data)

	def test_lookup_external_cve_returns_copies(self):
		from secator.providers._base import CVEProvider
		from secator.providers.circl import circl
		base = Vulnerability(name='CVE-2099-0002', provider='test', tags=['t0'])
		CVEProvider.lookup_external_cve.cache_clear()
		with mock.patch.object(circl, 'lookup_cve', return_value=base) as m:
			first = CVEProvider.lookup_external_cve('CVE-2099-0002', provider='circl')
			first.tags.append('changed')
			second = CVEProvider.lookup_external_cve('CVE-2099-0002', provider='circl')
		CVEProvider.lookup_external_cve.cache_clear()
		self.assertEqual(m.call_count, 1)
		self.assertEqual(second.tags, ['t0'])
		self.assertEqual(base.tags, ['t0'])


class TestCrawlerOptions(unittest.TestCase):

	def test_category_option_lists_have_no_duplicates(self):
		from secator.tasks._categories import OPTS_HTTP_CRAWLERS, OPTS_HTTP_FUZZERS
		self.assertEqual(len(OPTS_HTTP_FUZZERS), len(set(OPTS_HTTP_FUZZERS)))
		self.assertEqual(len(OPTS_HTTP_CRAWLERS), len(set(OPTS_HTTP_CRAWLERS)))

	def test_crawlers_do_not_expose_body_or_replay_options(self):
		from secator.definitions import DATA, METHOD, REPLAY_PROXY, WORDLIST
		from secator.tasks._categories import HttpCrawler, OPTS_HTTP_CRAWLERS
		for opt in (DATA, METHOD, REPLAY_PROXY, WORDLIST):
			self.assertNotIn(opt, OPTS_HTTP_CRAWLERS)
			self.assertNotIn(opt, HttpCrawler.meta_opts)

	def test_crawler_command_lines_drop_unsupported_flags(self):
		from secator.loader import discover_tasks
		from secator.tasks._categories import HttpCrawler
		crawlers = [cls for cls in discover_tasks() if issubclass(cls, HttpCrawler)]
		self.assertTrue(crawlers)
		for cls in crawlers:
			task = cls('http://example.com', data='x=1', replay_proxy='http://127.0.0.1:8080', dry_run=True, print_cmd=False)
			self.assertNotIn('x=1', task.cmd, cls.__name__)
			self.assertNotIn('127.0.0.1:8080', task.cmd, cls.__name__)

	def test_fuzzers_keep_body_and_replay_options(self):
		from secator.tasks.ffuf import ffuf
		task = ffuf(
			'http://example.com/FUZZ', data='x=1', replay_proxy='http://127.0.0.1:8080', dry_run=True, print_cmd=False)
		self.assertIn('x=1', task.cmd)
		self.assertIn('127.0.0.1:8080', task.cmd)


class TestMutableDefaults(unittest.TestCase):

	def test_check_test_default_results_not_shared(self):
		from secator.cli import check_test
		with mock.patch('secator.cli.console'):
			check_test(False, 'm', 'fail')
		self.assertIsNone(inspect.signature(check_test).parameters['results'].default)

	def test_start_runner_defaults_are_none(self):
		from secator.celery import start_runner
		params = inspect.signature(start_runner.run).parameters
		for name in ('results', 'run_opts', 'hooks', 'validators', 'context'):
			self.assertIsNone(params[name].default, name)


class TestJdwpShellifierDefaults(unittest.TestCase):

	def test_break_on_defaults_to_detection_sentinel(self):
		from secator.tasks.jdwp_shellifier import DETECT_BREAK_ON, jdwp_shellifier
		self.assertEqual(jdwp_shellifier.opts['break_on']['default'], DETECT_BREAK_ON)
		task = jdwp_shellifier('10.0.0.1', dry_run=True, print_cmd=False)
		self.assertIn(f'--break-on {DETECT_BREAK_ON}', task.cmd)
		self.assertNotIn('--cmd', task.cmd)

	def test_break_on_can_be_overridden(self):
		from secator.tasks.jdwp_shellifier import jdwp_shellifier
		task = jdwp_shellifier('10.0.0.1', break_on='java.lang.String.indexOf', dry_run=True, print_cmd=False)
		self.assertIn('--break-on java.lang.String.indexOf', task.cmd)
