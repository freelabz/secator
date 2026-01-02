import os
import unittest

from click.testing import CliRunner

from secator.cli import cli
from secator.runners import Command
from secator.rich import console

class TestCli(unittest.TestCase):

	def setUp(self):
		self.runner = CliRunner()

	# def test_cli_pipe(self):
	# 	pipe = 'secator x nmap -p 80 testphp.vulnweb.com | secator x httpx -json'
	# 	cmd = Command.execute(pipe, name='secator_pipe', quiet=True, cls_attributes={'shell': True})
	# 	console.print("Command secator_pipe finished with return code", cmd.return_code)
	# 	console.print(cmd.toDict())
	# 	port = '{"url": "http://testphp.vulnweb.com",'
	# 	assert cmd.return_code == 0
	# 	assert cmd.status == 'SUCCESS'
	# 	assert port in cmd.output
	# 	assert "Task httpx finished with status SUCCESS" in cmd.output
	# 	assert "Task nmap finished with status SUCCESS" in cmd.output

	def test_task_input_required(self):
		result = self.runner.invoke(cli, ['task', 'nmap'])
		assert result.exception
		assert result.exit_code == 1
		assert 'No input passed on stdin. Showing help page.' in result.output

	def test_task_input_not_required(self):
		result = self.runner.invoke(cli, ['task', 'arpscan'])
		assert not result.exception
		assert result.exit_code == 0
		assert 'No inputs provided, using default inputs:' in result.output

	def test_task_input_not_required_with_no_default_inputs(self):
		result = self.runner.invoke(cli, ['task', 'arp'])
		assert not result.exception
		assert result.exit_code == 0
