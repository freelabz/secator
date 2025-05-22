import io
import unittest
from secator.cli import ALL_SCANS, ALL_WORKFLOWS, ALL_TASKS
from secator.runners import Workflow, Scan
from secator.workflows import DYNAMIC_WORKFLOWS
from secator.scans import DYNAMIC_SCANS
from secator.utils_test import META_OPTS
from secator.rich import console
from contextlib import redirect_stdout, redirect_stderr


class TestTemplates(unittest.TestCase):

	def test_tasks(self):
		console.print('')
		for task in ALL_TASKS:
			with self.subTest(name=task.__name__):
				console.print(f'\tTesting task {task.__name__} ...', end='')
				with io.StringIO() as buffer, redirect_stdout(buffer), redirect_stderr(buffer):
					task = task('TARGET', dry_run=True, print_cmd=True, **META_OPTS)
					task.run()
				console.print(' [green]ok[/]')

	def test_workflows(self):
		console.print('')
		for workflow in ALL_WORKFLOWS:
			with self.subTest(name=workflow.name):
				console.print(f'\tTesting workflow {workflow.name} ...', end='')
				with io.StringIO() as buffer, redirect_stdout(buffer), redirect_stderr(buffer):
					workflow = Workflow(workflow, run_opts={'dry_run': True, 'print_cmd': True, **META_OPTS})
					workflow.run()
				console.print(' [green]ok[/]')

	def test_scans(self):
		console.print('')
		for scan in ALL_SCANS:
			with self.subTest(name=scan.name):
				console.print(f'\tTesting scan {scan.name} ...', end='')
				with io.StringIO() as buffer, redirect_stdout(buffer), redirect_stderr(buffer):
					scan = Scan(scan, run_opts={'dry_run': True, 'print_cmd': True, **META_OPTS})
					scan.run()
				console.print(' [green]ok[/]')

	def test_workflows_dynamic_import(self):
		console.print('')
		for workflow_name, runner in DYNAMIC_WORKFLOWS.items():
			with self.subTest(name=workflow_name):
				console.print(f'\tTesting workflow {workflow_name} ...', end='')
				with io.StringIO() as buffer, redirect_stdout(buffer), redirect_stderr(buffer):
					workflow = runner('TARGET', dry_run=True, print_cmd=True, **META_OPTS)
					workflow.run()
				console.print(' [green]ok[/]')

	def test_scans_dynamic_import(self):
		console.print('')
		for scan_name, runner in DYNAMIC_SCANS.items():
			with self.subTest(name=scan_name):
				console.print(f'\tTesting scan {scan_name} ...', end='')
				with io.StringIO() as buffer, redirect_stdout(buffer), redirect_stderr(buffer):
					scan = runner('TARGET', dry_run=True, print_cmd=True, **META_OPTS)
					scan.run()
				console.print(' [green]ok[/]')

	# def test_runner_configs(self):
	# 	ALL_CONFIGS = ALL_SCANS + ALL_WORKFLOWS
	# 	console.print('waiting ...')
	# 	for config in ALL_CONFIGS:
	# 		loader = TemplateLoader(input=config)
	# 		console.print('--------------------------------')
	# 		if loader.type == 'workflow':
	# 			console.print(f'Running workflow: {loader.name}')
	# 			workflow = Workflow(loader, run_opts={'dry_run': True, 'print_cmd': True, **META_OPTS})
	# 			workflow.run()
	# 		elif loader.type == 'scan':
	# 			console.print(f'Running scan: {loader.name}')
	# 			scan = Scan(loader, run_opts={'dry_run': True, 'print_cmd': True, **META_OPTS})
	# 			scan.run()

	# def test_runner_dynamic(self):
	# 	console.print('waiting ...')
	# 	for runner in ALL_TASKS:
	# 		console.print('--------------------------------')
	# 		console.print(f'Running task: {runner.__name__}')
	# 		task = runner('TARGET', dry_run=True, print_cmd=True, **META_OPTS)
	# 		task.run()

	# 	for workflow_name, runner in DYNAMIC_WORKFLOWS.items():
	# 		if not workflow_name == 'wordpress':
	# 			continue
	# 		console.print('--------------------------------')
	# 		console.print(f'Running workflow: {workflow_name}')
	# 		workflow = runner('TARGET', dry_run=True, print_cmd=True, sync=True, **META_OPTS)
	# 		results = workflow.run()
	# 		console.print(results)

	# 	for scan_name, runner in DYNAMIC_SCANS.items():
	# 		console.print('--------------------------------')
	# 		console.print(f'Running scan: {scan_name}')
	# 		scan = runner('TARGET', dry_run=True, print_cmd=True, **META_OPTS)
	# 		scan.run()
