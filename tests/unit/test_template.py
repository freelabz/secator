import os
import shutil
import unittest
import yaml

from secator.config import CONFIG
from secator.output_types import Vulnerability
from secator.utils_test import FIXTURES_DIR, clear_modules
from secator.loader import get_configs_by_type, find_templates, discover_tasks
from secator.tree import build_runner_tree
from secator.template import TemplateLoader, get_config_options


class TestTemplate(unittest.TestCase):

	def setUp(self):
		self.template_dir = CONFIG.dirs.templates
		self.custom_task_path = self.template_dir / 'ls.py'
		self.writeable_file = self.template_dir / 'test.txt'
		self.custom_workflow_path = self.template_dir / 'ls.yml'
		shutil.copyfile(f'{FIXTURES_DIR}/ls.py', self.custom_task_path)
		shutil.copyfile(f'{FIXTURES_DIR}/ls.yml', self.custom_workflow_path)
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
		find_templates.cache_clear()
		get_configs_by_type.cache_clear()
		discover_tasks.cache_clear()
		from secator.runners import Workflow
		ls_workflow = [w for w in get_configs_by_type('workflow') if w.name == 'ls'][0]
		self.assertIsNotNone(ls_workflow)
		workflow = Workflow(ls_workflow, inputs=[str(self.template_dir)])
		workflow.run()
		findings = workflow.findings
		self.assertEqual(len(findings), 1)
		vuln = [r for r in findings if r._type == 'vulnerability'][0]
		self.assertTrue(self.expected_vuln == Vulnerability.load(vuln.toDict()))


class TestTree(unittest.TestCase):

	def setUp(self):
		self.task_config = {
			'type': 'task',
			'name': 'nuclei'
		}
		self.workflow_config_1 = {
			'type': 'workflow',
			'name': 'test1',
			'default_options': {
				'ports': '80,443'
			},
			'options': {
				'nuclei': {'is_flag': True, 'default': False}
			},
			'tasks': {
				'nuclei/first': {'opt_1': 'test1', 'if': 'opts.nuclei'},
				'nmap': {'opt_2': 'test2'},
				'_group/1': {
					'httpx/first': {'opt_3': 'test3'},
					'nuclei/host': {'opt_4': 'test4', 'if': 'opts.nuclei'}
				},
				'_group/2': {
					'nuclei/network': {'opt_4': 'test4_new', 'opt_5': 'test5', 'if': 'opts.nuclei'},
					'httpx/network': {'opt_6': 'test6'}
				}
			}
		}
		self.workflow_config_2 = {
			'type': 'workflow',
			'name': 'test2',
			'options': {
				'nuclei': {'is_flag': True, 'default': False}
			},
			'tasks': {
				'nuclei/second': {'opt_1': 'test1', 'if': 'opts.nuclei'},
				'_group/1': {
					'httpx/second': {'opt_3': 'test3'},
					'dnsx/host': {'opt_4': 'test4', 'if': 'opts.nuclei'}
				},
				'_group/2': {
					'arjun': {'opt_4': 'test4_new', 'opt_5': 'test5', 'if': 'opts.nuclei'},
					'dnsx/network': {'opt_6': 'test6'}
				}
			}
		}
		self.scan_config = {
			'type': 'scan',
			'name': 'test',
			'workflows': {
				'test1': {},
				'test2': {}
			}
		}
		self.template_dir = CONFIG.dirs.templates
		self.custom_workflow_path_1 = self.template_dir / 'test.yml'
		self.custom_workflow_path_2 = self.template_dir / 'test2.yml'
		with open(self.custom_workflow_path_1, 'w') as f:
			f.write(yaml.dump(self.workflow_config_1, sort_keys=False))
		with open(self.custom_workflow_path_2, 'w') as f:
			f.write(yaml.dump(self.workflow_config_2, sort_keys=False))

	def test_tree_task(self):
		find_templates.cache_clear()
		config = TemplateLoader(input=self.task_config)
		tree = build_runner_tree(config)
		root_node = tree.root_nodes[0]
		self.assertEqual(root_node.name, 'nuclei')
		self.assertEqual(root_node.type, 'task')

	def test_tree_workflow_1(self):
		find_templates.cache_clear()
		config = TemplateLoader(input=self.workflow_config_1)
		tree = build_runner_tree(config)
		root_node = tree.root_nodes[0]
		self.assertEqual(root_node.name, 'test1')
		self.assertEqual(root_node.type, 'workflow')
		self.assertEqual(root_node.default_opts.toDict(), {'ports': '80,443'})
		self.assertEqual(len(root_node.children), 4)
		self.assertEqual(root_node.children[0].name, 'nuclei/first')
		self.assertEqual(root_node.children[1].name, 'nmap')
		self.assertEqual(root_node.children[2].children[0].name, 'httpx/first')
		self.assertEqual(root_node.children[2].children[1].name, 'nuclei/host')
		self.assertEqual(root_node.children[3].children[0].name, 'nuclei/network')
		self.assertEqual(root_node.children[3].children[1].name, 'httpx/network')

	def test_get_config_options_workflow_1(self):
		find_templates.cache_clear()
		config = TemplateLoader(input=self.workflow_config_1)
		opts = get_config_options(config)
		self.assertEqual(opts['ports']['default'], '80,443')
		self.assertEqual(opts['ports']['default_from'], 'test1')
		self.assertEqual(opts['ports']['prefix'], 'Workflow test1')
		self.assertEqual(opts['nuclei']['default'], False)
		self.assertEqual(opts['nuclei']['prefix'], 'Workflow test1')

	def test_get_config_options_scan(self):
		find_templates.cache_clear()
		config = TemplateLoader(input=self.scan_config)
		opts = get_config_options(config)
		# import json
		# print(json.dumps(opts, indent=4, default=str))
		self.assertEqual(opts['test1-nuclei']['default'], False)
		self.assertEqual(opts['test1-nuclei']['prefix'], 'Workflow test1')
		self.assertEqual(opts['test2-nuclei']['default'], False)
		self.assertEqual(opts['test2-nuclei']['prefix'], 'Workflow test2')

	def test_dry_run(self):
		from secator.runners import Scan
		find_templates.cache_clear()
		config = TemplateLoader(input=self.scan_config)
		scan = Scan(config, run_opts={'dry_run': True})
		scan.run()
		self.assertEqual(scan.status, 'SUCCESS')
		self.assertEqual(len(scan.errors), 0)
		# from secator.rich import console
		# tree = build_runner_tree(config)
		# console.print(tree.render_tree())
		# console.print('')
		messages = [r.message for r in scan.infos]
		self.assertIn('Skipped task [bold gold3]nuclei/first[/] because condition is not met: [bold green]opts.nuclei[/]', messages)
		self.assertIn('Skipped task [bold gold3]nuclei/second[/] because condition is not met: [bold green]opts.nuclei[/]', messages)
		self.assertIn('Skipped task [bold gold3]nuclei/host[/] because condition is not met: [bold green]opts.nuclei[/]', messages)
		self.assertIn('Skipped task [bold gold3]nuclei/network[/] because condition is not met: [bold green]opts.nuclei[/]', messages)

	def test_dry_run_with_condition_enabled(self):
		from secator.runners import Scan
		find_templates.cache_clear()
		from secator.template import TemplateLoader
		config = TemplateLoader(input=self.scan_config)
		scan = Scan(config, run_opts={'dry_run': True, 'test1_nuclei': True})
		scan.run()
		self.assertEqual(scan.status, 'SUCCESS')
		self.assertEqual(len(scan.infos), 11)
		self.assertEqual(len(scan.errors), 0)
		messages = [r.message for r in scan.infos]
		self.assertNotIn('Skipped task nuclei/first because condition is not met: opts.nuclei', messages)
		self.assertNotIn('Skipped task nuclei/network because condition is not met: opts.nuclei', messages)
		self.assertNotIn('Skipped task nuclei/host because condition is not met: opts.nuclei', messages)
