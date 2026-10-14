"""json on_build writes a PENDING child runner doc at build time (mongodb/sqlite parity)."""
import json
import unittest
from pathlib import Path
from tempfile import mkdtemp
from types import SimpleNamespace

from secator.hooks.json import on_build, _child_fqn
from secator.query.json import JsonBackend


class TestJsonOnBuild(unittest.TestCase):

	def test_child_fqn_matches_runner_fqn_rules(self):
		self.assertEqual(_child_fqn({'context': {'node_id': 'wf.httpx'}}), 'wf_httpx')
		self.assertEqual(_child_fqn({'name': 'nmap', 'chunk': 2}), 'nmap_2')

	def test_on_build_writes_pending_and_list_runners_sees_it(self):
		d = Path(mkdtemp()) / 'testws' / 'workflows' / '0'
		d.mkdir(parents=True)
		parent = SimpleNamespace(config=SimpleNamespace(type='workflow'), reports_folder=str(d))
		task_spec = {'name': 'httpx', 'context': {'node_id': 'wf.httpx', 'workflow_id': 'W'}}

		on_build(parent, task_spec)

		files = list(d.glob('report_*.json'))
		self.assertEqual([p.name for p in files], ['report_wf_httpx.json'])
		info = json.loads(files[0].read_text())['info']
		self.assertEqual(info['status'], 'PENDING')
		self.assertEqual(info['name'], 'httpx')
		self.assertEqual(info['config']['type'], 'task')      # child of a workflow is a task
		self.assertTrue(info['has_parent'])

		# The pending child now shows up in the run's tree BEFORE it runs.
		backend = JsonBackend('testws', config={'reports_dir': str(d.parents[2])})
		names = [r['name'] for r in backend.list_runners(report_dir=str(d))]
		self.assertEqual(names, ['httpx'])

	def test_on_build_does_not_clobber_a_started_child(self):
		d = Path(mkdtemp())
		path = d / 'report_wf_httpx.json'
		path.write_text(json.dumps({'info': {'name': 'httpx', 'status': 'RUNNING'}}))
		parent = SimpleNamespace(config=SimpleNamespace(type='workflow'), reports_folder=str(d))
		on_build(parent, {'name': 'httpx', 'context': {'node_id': 'wf.httpx'}})
		self.assertEqual(json.loads(path.read_text())['info']['status'], 'RUNNING')  # untouched


if __name__ == '__main__':
	unittest.main()
