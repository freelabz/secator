import threading
import unittest
from types import SimpleNamespace

from secator.output_types import Url
from tests.unit.test_sqlite_driver import SqliteTestBase


class TestSqliteConcurrentThreads(SqliteTestBase):
	"""Several threads of one process (e.g. an ai task's background jobs) write and read
	through the sqlite driver at the same time."""

	def test_each_thread_gets_its_own_connection(self):
		conns = {}
		both = threading.Barrier(2)

		def grab(name):
			conns[name] = self.sqlite_mod.get_sqlite_conn()
			both.wait(10)  # both threads alive at once: no thread ident reuse

		threads = [threading.Thread(target=grab, args=(i,)) for i in range(2)]
		for t in threads:
			t.start()
		for t in threads:
			t.join(10)
		self.assertIsNot(conns[0], conns[1])
		self.assertIs(self.sqlite_mod.get_sqlite_conn(), self.sqlite_mod.get_sqlite_conn())

	def test_concurrent_writes_and_reads(self):
		from secator.query.sqlite import SqliteBackend
		n_threads, n_items = 8, 40
		runner = SimpleNamespace()
		errors = []
		start = threading.Barrier(n_threads)

		def work(t):
			try:
				backend = SqliteBackend('ws', config={'db_path': self.db_path})
				start.wait(10)
				for i in range(n_items):
					item = Url(url=f'http://127.0.0.1/{t}/{i}', _context={'workspace_id': 'ws'})
					self.sqlite_mod.update_finding(runner, item)
					backend.count({'_type': 'url'})
			except Exception as e:  # noqa: BLE001 - collected for the assertion
				errors.append(repr(e))

		threads = [threading.Thread(target=work, args=(t,)) for t in range(n_threads)]
		for t in threads:
			t.start()
		for t in threads:
			t.join(60)
		self.assertEqual(errors, [])
		backend = SqliteBackend('ws', config={'db_path': self.db_path})
		self.assertEqual(backend.count({'_type': 'url'}), n_threads * n_items)

	def test_live_owner_connection_is_kept(self):
		"""A connection is only closed once the thread that opened it has ended."""
		mine = self.sqlite_mod.get_sqlite_conn()
		done = threading.Event()

		def other():
			self.sqlite_mod.get_sqlite_conn()
			done.set()

		t = threading.Thread(target=other)
		t.start()
		t.join(10)
		self.assertTrue(done.is_set())
		mine.execute('SELECT 1')  # still open
		self.assertIs(self.sqlite_mod.get_sqlite_conn(), mine)
		t2 = threading.Thread(target=self.sqlite_mod.get_sqlite_conn)  # opening prunes the ended thread's
		t2.start()
		t2.join(10)
		self.assertEqual(sum(1 for k in self.sqlite_mod._conns if k[1] == t.ident and t.ident != t2.ident), 0)


_GEVENT_SCRIPT = """
from gevent import monkey; monkey.patch_all()
import sys, threading, gevent
from secator.hooks import sqlite as m
db = sys.argv[1]
for spawn in (gevent.spawn, lambda f: threading.Thread(target=f)):
	res = {}
	def a():
		c = m.get_sqlite_conn(db)
		gevent.sleep(0.2)
		c.execute('SELECT 1')
		res['a'] = 'ok'
	def b():
		gevent.sleep(0.05)
		m.get_sqlite_conn(db)
		res['b'] = 'ok'
	tasks = [spawn(a), spawn(b)]
	for t in tasks:
		if isinstance(t, threading.Thread):
			t.start()
	for t in tasks:
		t.join()
	assert res == {'a': 'ok', 'b': 'ok'}, res
print('OK')
"""


class TestSqliteGevent(unittest.TestCase):

	def test_live_greenlet_keeps_its_connection(self):
		"""Under gevent a raw greenlet is not in threading.enumerate(): opening another connection
		must not close the one it is still using."""
		import os
		import subprocess
		import sys
		import tempfile
		try:
			import gevent  # noqa: F401
		except ImportError:
			self.skipTest('gevent not installed')
		db = os.path.join(tempfile.mkdtemp(), 'g.db')
		repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
		env = {**os.environ, 'PYTHONPATH': repo}
		out = subprocess.run([sys.executable, '-c', _GEVENT_SCRIPT, db], capture_output=True, text=True,
		                     env=env, timeout=120)
		self.assertIn('OK', out.stdout, out.stderr[-2000:])


if __name__ == '__main__':
	unittest.main()
