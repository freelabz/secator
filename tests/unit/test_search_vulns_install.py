"""search_vulns must leave its bundled SQLite databases read-only after install.

search_vulns opens its ~1.1 GB databases with a plain read-write `sqlite3.connect()`.
On a copy-on-write root filesystem (an overlayfs container layer), opening a lower-layer
file for writing copies the whole file into the writable layer, even for a read-only
query, so a single lookup can fill a small ephemeral-storage budget. Without the write
bit, SQLite opens the file read-only instead: no copy-up, same query results.
"""
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import unittest

from secator.tasks.search_vulns import search_vulns


class TestSearchVulnsInstall(unittest.TestCase):

	def test_update_still_runs_first_and_stays_best_effort(self):
		post = search_vulns.install_post['*']
		self.assertTrue(post.startswith('search_vulns -u || true; '))

	def test_post_install_drops_write_bit_on_bundled_dbs(self):
		post = search_vulns.install_post['*']
		self.assertIn('chmod a-w', post)
		self.assertIn('search_vulns/resources/*.db3', post)

	@unittest.skipIf(shutil.which('find') is None or shutil.which('readlink') is None, 'needs find + readlink')
	def test_post_install_command_makes_dbs_read_only(self):
		# Lay out a fake pipx venv: <venv>/bin/search_vulns + <venv>/lib/.../search_vulns/resources/*.db3,
		# with the entrypoint reached through a symlink in a separate bin dir (like pipx does).
		with tempfile.TemporaryDirectory() as tmp:
			venv = os.path.join(tmp, 'venvs', 'search-vulns')
			resources = os.path.join(venv, 'lib', 'python3', 'site-packages', 'search_vulns', 'resources')
			os.makedirs(resources)
			os.makedirs(os.path.join(venv, 'bin'))
			entry = os.path.join(venv, 'bin', 'search_vulns')
			with open(entry, 'w') as f:
				f.write('#!/bin/sh\nexit 0\n')
			os.chmod(entry, 0o755)
			bindir = os.path.join(tmp, 'bin')
			os.makedirs(bindir)
			os.symlink(entry, os.path.join(bindir, 'search_vulns'))
			db = os.path.join(resources, 'vulndb.db3')
			conn = sqlite3.connect(db)
			conn.execute('CREATE TABLE t (x)')
			conn.execute('INSERT INTO t VALUES (1)')
			conn.commit()
			conn.close()
			other = os.path.join(resources, 'other.json')
			open(other, 'w').close()

			env = dict(os.environ, PATH=f'{bindir}{os.pathsep}{os.environ.get("PATH", "")}')
			ret = subprocess.run(search_vulns.install_post['*'], shell=True, env=env, capture_output=True, text=True)
			self.assertEqual(ret.returncode, 0, ret.stderr)

			self.assertFalse(os.stat(db).st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
			self.assertTrue(os.stat(other).st_mode & stat.S_IWUSR)  # only the databases are touched
			# The database is still queryable.
			conn = sqlite3.connect(db)
			self.assertEqual(conn.execute('SELECT x FROM t').fetchone(), (1,))
			conn.close()


if __name__ == '__main__':
	unittest.main()
