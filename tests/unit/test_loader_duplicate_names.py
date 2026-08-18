"""Tests for the duplicate config-name warning (scans / workflows / tasks).

A second config with the same `name` silently shadows the first (name resolution keeps the first
match), so discovery warns about it — see secator.loader._warn_duplicate_names.
"""
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


if __name__ == '__main__':
	unittest.main()
