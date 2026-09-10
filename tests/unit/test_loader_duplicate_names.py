"""Tests for the duplicate config-name warning (scans / workflows / tasks).

A second config with the same `name` silently shadows the first (name resolution keeps the first
match), so discovery warns about it — see secator.loader._warn_duplicate_names.
"""
import contextlib
import unittest
from unittest.mock import patch

from secator import loader


def _printed(mock):
	return '\n'.join(str(c.args[0]) for c in mock.call_args_list if c.args)


class TestDuplicateNameWarning(unittest.TestCase):

	def test_warns_on_duplicate_label(self):
		with patch.object(loader.console, 'print') as mock:
			loader._warn_duplicate_names(
				[('workflow "host_recon"', 'a.yaml'), ('workflow "host_recon"', 'b.yaml')],
				_seen=set(),
			)
		out = _printed(mock)
		self.assertIn('Duplicate workflow "host_recon"', out)
		self.assertIn('a.yaml', out)
		self.assertIn('b.yaml', out)

	def test_no_warning_when_unique(self):
		with patch.object(loader.console, 'print') as mock:
			loader._warn_duplicate_names(
				[('workflow "a"', 'a.yaml'), ('workflow "b"', 'b.yaml')],
				_seen=set(),
			)
		self.assertEqual(mock.call_count, 0)

	def test_no_warning_when_same_source_repeated(self):
		# Re-entrant discovery can list the same file twice; that must not be a false positive.
		with patch.object(loader.console, 'print') as mock:
			loader._warn_duplicate_names(
				[('task "nmap"', 'nmap.py'), ('task "nmap"', 'nmap.py')],
				_seen=set(),
			)
		self.assertEqual(mock.call_count, 0)

	def test_warns_only_once_per_label(self):
		seen = set()
		entries = [('scan "s"', 'x.yaml'), ('scan "s"', 'y.yaml')]
		with patch.object(loader.console, 'print') as mock:
			loader._warn_duplicate_names(list(entries), _seen=seen)
			first = mock.call_count
			loader._warn_duplicate_names(list(entries), _seen=seen)
			second = mock.call_count
		self.assertGreater(first, 0)
		self.assertEqual(first, second, 'duplicate should be reported only once per process')

	def test_discover_tasks_warns_on_same_stem_external_shadowing(self):
		# Two external files with the same stem in different dirs: discover_external_tasks reuses
		# the first module for the second, so both classes are identical and cls.__module__ points
		# both at the first file — hiding the duplicate. The per-file sources side channel keeps
		# both real paths so the shadowing is still reported.
		nmap = type('nmap', (), {})
		patches = [
			patch.object(loader, 'discover_external_tasks', return_value=[nmap, nmap]),
			patch.object(loader, 'discover_internal_tasks', return_value=[]),
			patch.object(loader, '_external_task_sources', [('nmap', '/a/nmap.py'), ('nmap', '/b/nmap.py')]),
			patch.object(loader, '_warned_duplicate_names', set()),
		]
		with contextlib.ExitStack() as stack:
			mock = stack.enter_context(patch.object(loader.console, 'print'))
			for p in patches:
				stack.enter_context(p)
			loader.discover_tasks.cache_clear()
			try:
				loader.discover_tasks()
			finally:
				loader.discover_tasks.cache_clear()
		out = _printed(mock)
		self.assertIn('Duplicate task "nmap"', out)
		self.assertIn('/a/nmap.py', out)
		self.assertIn('/b/nmap.py', out)


if __name__ == '__main__':
	unittest.main()
