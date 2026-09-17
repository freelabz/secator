"""JsonBackend.list_runners must surface per-child report_*.json under a report_dir.

Before this, list_runners only read files literally named report.json (via list_reports), so the
individual tasks composing a workflow/scan were never returned for the json backend — the
"parked follow-up" noted in secator/hooks/json.py. This is required for store-driven live polling.
"""
import json
import unittest
from pathlib import Path
from tempfile import mkdtemp

from secator.query.json import JsonBackend


def _write(path: Path, info: dict):
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(json.dumps({'info': info}))


class TestJsonListRunnersReportDir(unittest.TestCase):

	def setUp(self):
		self.root = Path(mkdtemp())
		self.scan_dir = self.root / 'testws' / 'scans' / '0'
		_write(self.scan_dir / 'report.json', {
			'name': 'myscan', 'status': 'RUNNING', 'has_parent': False,
			'config': {'type': 'scan'}, 'progress': 40,
		})
		# Child task lives in the SAME dir as its parent scan (json shards per-child by fqn).
		_write(self.scan_dir / 'report_myscan_httpx_0.json', {
			'name': 'httpx', 'status': 'RUNNING', 'has_parent': True,
			'config': {'type': 'task'}, 'progress': 10,
		})
		self.backend = JsonBackend('testws', config={'reports_dir': str(self.root)})

	def test_report_dir_returns_full_tree(self):
		runners = self.backend.list_runners(report_dir=str(self.scan_dir))
		names = sorted(r['name'] for r in runners)
		self.assertEqual(names, ['httpx', 'myscan'])
		# Child type comes from info.config.type, not the (parent's) directory path.
		by_name = {r['name']: r for r in runners}
		self.assertEqual(by_name['httpx']['_type'], 'task')
		self.assertEqual(by_name['myscan']['_type'], 'scan')

	def test_has_parent_filter(self):
		children = self.backend.list_runners(report_dir=str(self.scan_dir), has_parent=True)
		self.assertEqual([r['name'] for r in children], ['httpx'])
		roots = self.backend.list_runners(report_dir=str(self.scan_dir), has_parent=False)
		self.assertEqual([r['name'] for r in roots], ['myscan'])


if __name__ == '__main__':
	unittest.main()
