# tests/unit/test_sqlite_driver.py

import tempfile
import unittest
from pathlib import Path


class SqliteTestBase(unittest.TestCase):
	"""Points the sqlite driver at a temp DB and resets the connection cache."""

	def setUp(self):
		import secator.hooks.sqlite as sqlite_mod
		from secator.config import CONFIG
		self.sqlite_mod = sqlite_mod
		self.temp_dir = tempfile.mkdtemp()
		self.db_path = str(Path(self.temp_dir) / 'test.db')
		self._orig_path = CONFIG.addons.sqlite.path
		CONFIG.addons.sqlite.path = self.db_path
		sqlite_mod._conns.clear()

	def tearDown(self):
		import shutil
		from secator.config import CONFIG
		for conn in self.sqlite_mod._conns.values():
			conn.close()
		self.sqlite_mod._conns.clear()
		CONFIG.addons.sqlite.path = self._orig_path
		shutil.rmtree(self.temp_dir)


class TestSqliteConnection(SqliteTestBase):
	def test_schema_created(self):
		conn = self.sqlite_mod.get_sqlite_conn()
		tables = {
			r[0] for r in conn.execute(
				"SELECT name FROM sqlite_master WHERE type='table'").fetchall()
		}
		self.assertEqual({'findings', 'tasks', 'workflows', 'scans'}, tables & {'findings', 'tasks', 'workflows', 'scans'})

	def test_wal_mode(self):
		conn = self.sqlite_mod.get_sqlite_conn()
		mode = conn.execute('PRAGMA journal_mode').fetchone()[0]
		self.assertEqual(mode.lower(), 'wal')

	def test_regexp_function_registered(self):
		conn = self.sqlite_mod.get_sqlite_conn()
		row = conn.execute("SELECT 'CVE-2026-1' REGEXP 'CVE-2026'").fetchone()
		self.assertEqual(row[0], 1)
		row = conn.execute("SELECT 'foo' REGEXP 'CVE'").fetchone()
		self.assertEqual(row[0], 0)

	def test_regexp_none_value(self):
		self.assertFalse(self.sqlite_mod._regexp('CVE', None))

	def test_regexp_none_pattern(self):
		self.assertFalse(self.sqlite_mod._regexp(None, 'CVE-2026'))

	def test_regexp_invalid_pattern_returns_false(self):
		# An unbalanced group is an invalid regex; should be swallowed (return False), not raise.
		self.assertFalse(self.sqlite_mod._regexp('(unclosed', 'anything'))

	def test_regexp_leading_wildcard_stripped(self):
		self.assertTrue(self.sqlite_mod._regexp('*CVE', 'a-CVE-2026'))


class TestComputeDuplicateUpdates(unittest.TestCase):
	def _finding(self, uuid_, url, fp=False, related=None):
		from secator.output_types import Url
		item = Url(url=url, _context={'workspace_id': 'ws1', 'workspace_duplicate': False})
		item._uuid = uuid_
		item._related = related or []
		item.is_false_positive = fp
		return item

	def test_marks_duplicates(self):
		from secator.hooks._dedup import compute_duplicate_updates
		a = self._finding('u1', 'http://x/a')
		b = self._finding('u2', 'http://x/a')  # duplicate of a
		c = self._finding('u3', 'http://x/c')  # unique
		updates = compute_duplicate_updates([], [a, b, c], copy_fields=[])
		# The first item keeps workspace_duplicate False and lists its duplicates
		self.assertFalse(updates['u1']['_context.workspace_duplicate'])
		self.assertIn('u2', updates['u1']['_related'])
		self.assertTrue(updates['u1']['_tagged'])
		# The duplicate is flagged
		self.assertTrue(updates['u2']['_context.workspace_duplicate'])
		self.assertTrue(updates['u2']['_tagged'])
		# Unique item is not a duplicate
		self.assertFalse(updates['u3']['_context.workspace_duplicate'])

	def test_no_duplicates(self):
		from secator.hooks._dedup import compute_duplicate_updates
		a = self._finding('u1', 'http://x/a')
		b = self._finding('u2', 'http://x/b')
		updates = compute_duplicate_updates([], [a, b], copy_fields=[])
		self.assertFalse(updates['u1']['_context.workspace_duplicate'])
		self.assertFalse(updates['u2']['_context.workspace_duplicate'])

	def test_workspace_duplicate_path(self):
		from secator.hooks._dedup import compute_duplicate_updates
		# An already-tagged workspace finding 'w1' matches a new untagged item 'u1' (same url).
		# w1 carries its own _related history ['old'].
		ws_finding = self._finding('w1', 'http://x/a', related=['old'])
		new_item = self._finding('u1', 'http://x/a')
		updates = compute_duplicate_updates([ws_finding], [new_item], copy_fields=[])
		# The new item is the main, not a duplicate, and is tagged.
		self.assertFalse(updates['u1']['_context.workspace_duplicate'])
		self.assertTrue(updates['u1']['_tagged'])
		# It relates to the matching workspace finding and inherits its _related history.
		self.assertIn('w1', updates['u1']['_related'])
		self.assertIn('old', updates['u1']['_related'])
		# The matching workspace finding is flagged as a duplicate.
		self.assertTrue(updates['w1']['_context.workspace_duplicate'])
		self.assertTrue(updates['w1']['_tagged'])

	def test_copy_fields_from_previous_main(self):
		from secator.hooks._dedup import compute_duplicate_updates
		# Previous main (workspace) finding has a non-empty field; new item lacks it -> copied.
		ws_finding = self._finding('w1', 'http://x/a')
		ws_finding.host = 'example.com'  # non-empty on previous main
		new_item = self._finding('u1', 'http://x/a')
		new_item.host = ''  # empty on new item -> should be filled from previous
		updates = compute_duplicate_updates([ws_finding], [new_item], copy_fields=['host'])
		self.assertEqual(updates['u1'].get('host'), 'example.com')
