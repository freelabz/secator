"""Tests for AI read_file / write_file tools + their per-path permission gating."""

import os
import tempfile
import unittest

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext, dispatch_action
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.guardrails import PermissionEngine
	from secator.output_types import Ai, Error


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestFileTools(unittest.TestCase):

	def setUp(self):
		self.tmp = tempfile.mkdtemp()

	def _ctx(self):
		return ActionContext(targets=[], model='m', context={'workspace_id': 'ws'})

	def test_tools_exposed(self):
		for mode in ('attack', 'chat', 'exploit'):
			names = [s['function']['name'] for s in build_tool_schemas(mode)]
			self.assertIn('read_file', names, mode)
			self.assertIn('write_file', names, mode)

	def test_tool_call_mapping(self):
		self.assertEqual(tool_call_to_action('read_file', {'path': '/x'})['action'], 'read_file')
		self.assertEqual(tool_call_to_action('write_file', {'path': '/x', 'content': 'y'})['action'], 'write_file')

	def test_write_then_read_roundtrip(self):
		path = os.path.join(self.tmp, 'note.txt')
		out = list(dispatch_action({'action': 'write_file', 'path': path, 'content': 'hello'}, self._ctx()))
		self.assertTrue(any(isinstance(o, Ai) and o.ai_type == 'write_file' for o in out))
		self.assertEqual(open(path).read(), 'hello')
		out = list(dispatch_action({'action': 'read_file', 'path': path}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai) and o.ai_type == 'read_file']
		self.assertEqual(ai[0].content, 'hello')

	def test_write_append(self):
		path = os.path.join(self.tmp, 'a.txt')
		list(dispatch_action({'action': 'write_file', 'path': path, 'content': 'a'}, self._ctx()))
		list(dispatch_action({'action': 'write_file', 'path': path, 'content': 'b', 'append': True}, self._ctx()))
		self.assertEqual(open(path).read(), 'ab')

	def test_write_creates_parent_dirs(self):
		path = os.path.join(self.tmp, 'deep', 'x', 'f.txt')
		list(dispatch_action({'action': 'write_file', 'path': path, 'content': 'z'}, self._ctx()))
		self.assertTrue(os.path.isfile(path))

	def test_read_missing_file_errors(self):
		out = list(dispatch_action({'action': 'read_file', 'path': os.path.join(self.tmp, 'nope')}, self._ctx()))
		self.assertTrue(any(isinstance(o, Error) for o in out))

	def test_read_truncates(self):
		path = os.path.join(self.tmp, 'big.txt')
		open(path, 'w').write('x' * 500)
		out = list(dispatch_action({'action': 'read_file', 'path': path, 'max_bytes': 100}, self._ctx()))
		ai = [o for o in out if isinstance(o, Ai)][0]
		self.assertTrue(ai.extra_data['truncated'])
		self.assertIn('truncated', ai.content)

	def test_missing_path_errors(self):
		self.assertTrue(any(isinstance(o, Error) for o in dispatch_action({'action': 'read_file'}, self._ctx())))
		wf = dispatch_action({'action': 'write_file', 'content': 'x'}, self._ctx())
		self.assertTrue(any(isinstance(o, Error) for o in wf))


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestFilePathGuardrails(unittest.TestCase):
	"""The whole point of the file tools: per-path permission matching."""

	def test_read_allowed_within_allowed_path(self):
		e = PermissionEngine(config={'allow': ['read(/work/*)'], 'deny': [], 'ask': []})
		self.assertEqual(e.check_action({'action': 'read_file', 'path': '/work/a.txt'}).decision, 'allow')

	def test_write_denied_by_explicit_deny(self):
		e = PermissionEngine(config={'allow': ['write(/work/*)'], 'deny': ['write(/etc/*)'], 'ask': []})
		self.assertEqual(e.check_action({'action': 'write_file', 'path': '/etc/passwd'}).decision, 'deny')

	def test_unknown_path_asks(self):
		e = PermissionEngine(config={'allow': ['read(/work/*)'], 'deny': [], 'ask': []})
		r = e.check_action({'action': 'read_file', 'path': '/somewhere/else'})
		self.assertEqual(r.decision, 'ask')
		self.assertIn('/somewhere/else', r.paths)

	def test_isolation_drops_unknown_path_ask(self):
		e = PermissionEngine(config={'allow': ['read(/work/*)'], 'deny': [], 'ask': []}, isolated=True)
		# unknown path would ask, but isolation makes the sandbox the fs boundary -> allow
		self.assertEqual(e.check_action({'action': 'read_file', 'path': '/somewhere/else'}).decision, 'allow')

	def test_isolation_still_honors_explicit_deny(self):
		e = PermissionEngine(config={'allow': [], 'deny': ['write(/etc/*)'], 'ask': []}, isolated=True)
		self.assertEqual(e.check_action({'action': 'write_file', 'path': '/etc/x'}).decision, 'deny')


if __name__ == '__main__':
	unittest.main()
