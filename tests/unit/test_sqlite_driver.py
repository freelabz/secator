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
