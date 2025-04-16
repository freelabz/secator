import os
import shutil
import unittest

from unittest.mock import patch

from secator.config import CONFIG
from secator.output_types import Vulnerability
from secator.utils_test import FIXTURES_DIR, clear_modules


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
		workflow = Workflow(ls_workflow, inputs=[str(self.template_dir)])
		workflow.run()
		findings = workflow.findings
		self.assertEqual(len(findings), 1)
		vuln = [r for r in findings if r._type == 'vulnerability'][0]
		self.assertTrue(self.expected_vuln == Vulnerability.load(vuln.toDict()))


class TestTemplateLoader(unittest.TestCase):

	def setUp(self):
		self.task_config = {
			'type': 'task',
			'name': 'nuclei'
		}
		self.workflow_config = {
			'type': 'workflow',
			'name': 'test',
			'tasks': {
				'nuclei': {'opt_1': 'test1'},
				'nmap': {'opt_2': 'test2'},
				'_group': {
					'httpx': {'opt_3': 'test3'},
					'nuclei/host': {'opt_4': 'test4'}
				},
				'nuclei/network': {'opt_4': 'test4_new', 'opt_5': 'test5'}
			}
		}
		self.scan_config = {
			'type': 'scan',
			'name': 'test',
			'workflows': {
				'test/1': {},
				'test/2': {}
			}
		}

	def test_extract_tasks_and_supported_opts_task(self):
		# Test different configurations
		from secator.tasks import nuclei
		from secator.template import TemplateLoader
		loader = TemplateLoader(input=self.task_config)
		tasks = loader._extract_tasks()
		self.assertEqual(list(tasks.keys()), ['nuclei'])
		self.assertEqual(tasks['nuclei']['class'], nuclei)

	def test_extract_tasks_and_supported_opts_workflow(self):
		# Test different configurations
		from secator.runners import Task
		from secator.template import TemplateLoader
		loader = TemplateLoader(input=self.workflow_config)
		tasks = loader._extract_tasks()
		self.assertEqual(list(tasks.keys()), ['nuclei', 'nmap', 'httpx', 'nuclei/host', 'nuclei/network'])
		for task, task_config in tasks.items():
			self.assertEqual(task.split('/')[0], task_config['name'])
			self.assertEqual(task_config['class'], Task.get_task_class(task_config['name']))
		self.assertEqual(tasks['nuclei']['opts'], {'opt_1': 'test1'})
		self.assertEqual(tasks['nmap']['opts'], {'opt_2': 'test2'})
		self.assertEqual(tasks['httpx']['opts'], {'opt_3': 'test3'})
		self.assertEqual(tasks['nuclei/host']['opts'], {'opt_4': 'test4'})
		self.assertEqual(tasks['nuclei/network']['opts'], {'opt_4': 'test4_new', 'opt_5': 'test5'})

	@patch('secator.template.TemplateLoader._load')
	def test_extract_tasks_and_supported_opts_scan(self, mock_load):
		from secator.template import TemplateLoader, TEMPLATES
		mock_load.return_value = self.workflow_config

		# Check if the loader is added to the TEMPLATES list correctly
		loader_wf = TemplateLoader(input=self.workflow_config)
		loader_wf.add_to_templates()
		self.assertIn(loader_wf, TEMPLATES)

		# Check if loading workflow by name gives the same object
		loader_wf_by_name = TemplateLoader(name='workflow/test')
		self.assertEqual(loader_wf, loader_wf_by_name)

		# Check if the tasks are extracted correctly
		wf_tasks = loader_wf._extract_tasks()
		loader_scan = TemplateLoader(input=self.scan_config)
		loader_scan.add_to_templates()
		self.assertIn(loader_scan, TEMPLATES)

		# Check if loading scan by name gives the same object
		loader_scan_by_name = TemplateLoader(name='scan/test')
		self.assertEqual(loader_scan, loader_scan_by_name)

		# Check if the tasks are extracted correctly
		scan_tasks = loader_scan._extract_tasks()
		expected_scan_tasks = {}
		for workflow in ['test/1', 'test/2']:
			for task, task_conf in wf_tasks.items():
				expected_scan_tasks[f'{workflow}/{task}'] = task_conf
		self.assertEqual(scan_tasks, expected_scan_tasks)
