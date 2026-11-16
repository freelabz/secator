# tests/unit/test_ai_guardrails_targets.py
"""Target normalization for shell commands: UNC / scheme / user@host / IPv6 forms, and
the approve-then-recheck round trip (what the user approves is exactly what is checked)."""
import unittest
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.config import CONFIG
	from secator.ai.actions import ActionContext, check_guardrails_sync
	from secator.ai.guardrails import (
		PermissionEngine, build_target_choices, detect_paths, extract_command_targets, normalize_target,
	)
	from secator.ai.interactivity import InteractivityBackend, RemoteBackend


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestNormalizeTarget(unittest.TestCase):

	def test_table(self):
		cases = {
			'//localhost': 'localhost',
			'//host/share': 'host',
			'\\\\host\\share': 'host',
			'smb://host/share': 'host',
			'smb://user:pw@host:445/share': 'host:445',
			'//10.0.0.5/c$': '10.0.0.5',
			'//[::1]/share': '[::1]',
			# unchanged forms
			'host:445': 'host:445',
			'[::1]:445': '[::1]:445',
			'example.com': 'example.com',
			'http://example.com/a': 'http://example.com/a',
			'10.0.0.0/8': '10.0.0.0/8',
			'/etc/passwd': '/etc/passwd',
		}
		for raw, expected in cases.items():
			with self.subTest(raw=raw):
				self.assertEqual(normalize_target(raw), expected)

	def test_choices_built_from_normalized_form(self):
		rules = build_target_choices('//localhost')[0]['rules']
		self.assertEqual(rules, ['target(localhost)'])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestExtractCommandTargets(unittest.TestCase):

	def _check(self, command, targets, paths=()):
		with patch('secator.ai.guardrails._resolves', return_value=True):
			self.assertEqual(extract_command_targets(command), list(targets))
		self.assertEqual(detect_paths(command), list(paths))

	def test_unc_and_smb_forms(self):
		cases = [
			('smbclient -L //localhost', ['localhost']),
			('smbclient //host/share -N', ['host']),
			('smbclient \\\\\\\\host\\\\share', ['host']),
			('smbclient smb://host/share', ['host']),
			('smbclient -L //10.0.0.5', ['10.0.0.5']),
			('ls //nas.example.com/share', ['nas.example.com']),
		]
		for command, targets in cases:
			with self.subTest(command=command):
				self._check(command, targets)

	def test_user_host_port_ipv6(self):
		cases = [
			('ssh root@localhost', ['localhost']),
			('ssh admin@10.0.0.9', ['10.0.0.9']),
			('scp f admin@10.0.0.9:/tmp/', ['10.0.0.9']),
			('nc localhost:445', ['localhost:445']),
			('nc [::1] 445', ['[::1]']),
			('curl http://[::1]:8080/', ['http://[::1]:8080/']),
			('curl https://example.com/x', ['https://example.com/x']),
		]
		for command, targets in cases:
			with self.subTest(command=command):
				self._check(command, targets)

	def test_paths_are_not_targets(self):
		self._check('cat /etc/passwd', [], ['/etc/passwd'])
		# `//etc` in a local command is a POSIX path, not a host
		self._check('cat //etc/passwd', [], ['/etc/passwd'])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestApproveThenRecheck(unittest.TestCase):
	"""End to end through check_guardrails: approve every prompt, the command must run."""

	def _run(self, command, answer='allow'):
		prompts = []

		class Backend(InteractivityBackend):
			def ask_user(self, question, choices, session_id, prompt_type='stopped', **ctx):
				prompts.append((ctx.get('permission_type'), ctx.get('value')))
				if answer == 'deny':
					return {'answer': 'deny'}
				RemoteBackend._add_permission_rules(
					ctx['engine'], ctx['permission_type'], ctx['value'], all_scope=(answer == 'allow_all'))
				return {'answer': 'allow'}

		engine = PermissionEngine(dict(CONFIG.addons.ai.permissions), targets=['example.com'], workspace='/tmp/ws')
		ctx = ActionContext(targets=['example.com'], model='x', permission_engine=engine, backend=Backend())
		denial, _ = check_guardrails_sync({'action': 'shell', 'command': command}, ctx)
		return denial, prompts, engine

	def test_unc_target_prompted_as_host_and_approval_unblocks(self):
		for answer in ('allow', 'allow_all'):
			with self.subTest(answer=answer):
				denial, prompts, _ = self._run('smbclient -L //localhost', answer)
				self.assertIsNone(denial)
				self.assertIn(('target', 'localhost'), prompts)
				self.assertFalse([p for p in prompts if p[0] in ('read', 'write')])

	def test_approval_does_not_cover_other_targets(self):
		# allow_all also grants shell(smbclient), so only the target layer is left to gate
		_, _, engine = self._run('smbclient -L //localhost', 'allow_all')
		res = engine.check_action({'action': 'shell', 'command': 'smbclient -L //10.0.0.5'})
		self.assertEqual(res.decision, 'ask')
		self.assertEqual(res.targets, ['10.0.0.5'])

	def test_denied_target_stays_blocked(self):
		denial, _, _ = self._run('smbclient -L //localhost', 'deny')
		self.assertIsNotNone(denial)

	def test_allow_all_top_level_path_unblocks(self):
		denial, prompts, _ = self._run('cat /foo', 'allow_all')
		self.assertIsNone(denial)
		self.assertEqual(prompts, [('read', '/foo')])

	def test_bracketed_ipv6_approval_matches(self):
		denial, prompts, _ = self._run('nc [::1] 445')
		self.assertIsNone(denial)
		self.assertIn(('target', '[::1]'), prompts)


if __name__ == '__main__':
	unittest.main()
