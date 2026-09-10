"""SqliteBackend.list_runners reads runner docs from the tasks/workflows/scans JSON-blob tables.

Regression guard for the store-driven live poll: the poll reads each runner's status/progress via
list_runners(). SqliteBackend inherited the base stub (returned []), so on sqlite the poll saw
status=None forever — panel stuck PENDING, never exited. It must unpack the `data` blobs like the
mongodb backend does.
"""
import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import mkdtemp

from secator.query.sqlite import SqliteBackend


def _mkdb(rows):
	db = str(Path(mkdtemp()) / 't.db')
	conn = sqlite3.connect(db)
	for t in ('tasks', 'workflows', 'scans'):
		conn.execute(f'CREATE TABLE {t} (id TEXT PRIMARY KEY, workspace_id TEXT, data TEXT)')
	for table, _id, ws, doc in rows:
		conn.execute(f'INSERT INTO {table} (id, workspace_id, data) VALUES (?, ?, ?)',
					 (_id, ws, json.dumps(doc)))
	conn.commit()
	conn.close()
	return db


class TestSqliteListRunners(unittest.TestCase):

	def _backend(self, rows):
		return SqliteBackend('ws', config={'db_path': _mkdb(rows)})

	def test_returns_runner_docs_with_status_and_context(self):
		wf = {'name': 'mini', 'status': 'SUCCESS', 'has_parent': False,
			  'context': {'workflow_id': 'W', 'celery_id': 'c0'}, 'progress': 100}
		tk = {'name': 'nmap', 'status': 'SUCCESS', 'has_parent': True,
			  'context': {'workflow_id': 'W', 'celery_id': 'c1'}, 'progress': 100}
		b = self._backend([('workflows', 'W', 'ws', wf), ('tasks', 'T', 'ws', tk)])
		runners = b.list_runners()
		self.assertEqual(sorted(r['name'] for r in runners), ['mini', 'nmap'])
		wf_doc = next(r for r in runners if r['name'] == 'mini')
		self.assertEqual(wf_doc['status'], 'SUCCESS')                 # status readable -> poll can exit
		self.assertEqual(wf_doc['context']['celery_id'], 'c0')        # matched to the panel by celery id
		self.assertFalse(wf_doc['has_parent'])                       # root detectable

	def test_has_parent_filter_returns_only_roots(self):
		wf = {'name': 'mini', 'has_parent': False, 'status': 'RUNNING', 'context': {}}
		tk = {'name': 'nmap', 'has_parent': True, 'status': 'RUNNING', 'context': {}}
		b = self._backend([('workflows', 'W', 'ws', wf), ('tasks', 'T', 'ws', tk)])
		roots = b.list_runners(has_parent=False)
		self.assertEqual([r['name'] for r in roots], ['mini'])

	def test_empty_db_returns_empty(self):
		self.assertEqual(self._backend([]).list_runners(), [])


if __name__ == '__main__':
	unittest.main()
