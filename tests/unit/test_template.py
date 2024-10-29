import unittest
from secator.config import CONFIG
from secator.output_types import Vulnerability
from secator.utils_test import FIXTURES_DIR, clear_modules
import os

import shutil


class TestTemplate(unittest.TestCase):
	def setUp(self):
		self.template_dir = CONFIG.dirs.templates
		self.custom_task_path = self.template_dir / 'ls.py'
		self.writeable_file = self.template_dir / 'test.txt'
		self.custom_workflow_path = self.template_dir / 'ls.yml'
		shutil.copy(f'{FIXTURES_DIR}/ls.py', self.custom_task_path)
		shutil.copy(f'{FIXTURES_DIR}/ls.yml', self.custom_workflow_path)
		self.writeable_file.touch()
		os.chmod(self.writeable_file, 0o007)
		self.expected_vuln = Vulnerability(
			name='World-writeable path',
			severity='high',
			confidence='high',
			provider='ls',
			matched_at=f'{str(self.writeable_file)}',
			_source='ls',
		)
		clear_modules()
		self.maxDiff = None

	def tearDown(self):
		self.custom_task_path.unlink()
		self.custom_workflow_path.unlink()
		self.writeable_file.unlink()

	def test_external_task(self):
		from secator.tasks import ls
		task = ls(str(self.template_dir))
		task.run()
		findings = task.findings
		self.assertEqual(len(findings), 1)
		self.assertTrue(self.expected_vuln == Vulnerability.load(findings[0].toDict()))

	def test_external_workflow(self):
		from secator.cli import ALL_WORKFLOWS
		from secator.runners import Workflow
		ls_workflow = [w for w in ALL_WORKFLOWS if w.name == 'ls'][0]
		self.assertIsNotNone(ls_workflow)
		workflow = Workflow(ls_workflow, targets=[str(self.template_dir)])
		workflow.run()
		findings = workflow.findings
		self.assertEqual(len(findings), 1)
		vuln = [r for r in findings if r._type == 'vulnerability'][0]
		self.assertTrue(self.expected_vuln == Vulnerability.load(vuln.toDict()))
