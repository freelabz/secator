# tests/unit/test_report_delete_e2e.py

"""End-to-end CLI tests for `secator r rm` deleting one or more runners."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

WORKSPACE = 'rm_e2e_ws'


class TestReportDeleteCli(unittest.TestCase):
	"""End-to-end CLI tests for `secator r rm` (local driver)."""

	def setUp(self):
		self.cli_runner = CliRunner()
		self.temp_dir = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.temp_dir, ignore_errors=True)

	def _make_runner(self, runner_type_plural, number):
		folder = Path(self.temp_dir) / WORKSPACE / runner_type_plural / str(number)
		folder.mkdir(parents=True, exist_ok=True)
		with open(folder / 'report.json', 'w') as f:
			json.dump({'info': {'name': 'test', 'context': {}}}, f)
		return folder

	def _exists(self, runner_type_plural, number):
		return (Path(self.temp_dir) / WORKSPACE / runner_type_plural / str(number)).exists()

	def _invoke(self, args):
		from secator.cli import cli

		with mock.patch('secator.cli.CONFIG') as mock_cfg:
			mock_cfg.dirs.reports = self.temp_dir
			mock_cfg.workspaces.current = WORKSPACE
			mock_cfg.addons.api.runner_delete_endpoint = '/api/{runner_type}/{runner_id}'
			return self.cli_runner.invoke(cli, ['r', 'rm', '-w', WORKSPACE, '-y'] + args)

	def test_space_separated_paths(self):
		self._make_runner('tasks', 23)
		self._make_runner('tasks', 24)
		self._make_runner('workflows', 21)
		result = self._invoke(['tasks/23', 'tasks/24', 'workflows/21'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		self.assertFalse(self._exists('tasks', 23))
		self.assertFalse(self._exists('tasks', 24))
		self.assertFalse(self._exists('workflows', 21))

	def test_comma_separated_paths(self):
		self._make_runner('tasks', 23)
		self._make_runner('tasks', 24)
		self._make_runner('workflows', 21)
		result = self._invoke(['tasks/23,tasks/24,workflows/21'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		self.assertFalse(self._exists('tasks', 23))
		self.assertFalse(self._exists('tasks', 24))
		self.assertFalse(self._exists('workflows', 21))

	def test_range_paths(self):
		for n in range(136, 141):
			self._make_runner('tasks', n)
		for n in range(10, 22):
			self._make_runner('workflows', n)
		# An out-of-range runner that must survive
		self._make_runner('tasks', 141)
		result = self._invoke(['tasks/136-140,workflows/10-21'])
		self.assertIsNone(result.exception, str(result.exception))
		self.assertEqual(result.exit_code, 0)
		for n in range(136, 141):
			self.assertFalse(self._exists('tasks', n))
		for n in range(10, 22):
			self.assertFalse(self._exists('workflows', n))
		self.assertTrue(self._exists('tasks', 141))

	def test_invalid_path_reported_and_skipped(self):
		self._make_runner('tasks', 23)
		result = self._invoke(['tasks/23', 'foo/1'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('Invalid runner type', result.output)
		self.assertFalse(self._exists('tasks', 23))

	def test_all_invalid_paths_aborts_without_deleting(self):
		result = self._invoke(['foo/1'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('Invalid runner type', result.output)

	def test_missing_folder_warns_but_succeeds(self):
		result = self._invoke(['tasks/999'])
		self.assertEqual(result.exit_code, 0)
		self.assertIn('not found', result.output.lower())

	def test_confirmation_prompt_abort(self):
		from secator.cli import cli

		self._make_runner('tasks', 23)
		with mock.patch('secator.cli.CONFIG') as mock_cfg:
			mock_cfg.dirs.reports = self.temp_dir
			mock_cfg.workspaces.current = WORKSPACE
			mock_cfg.addons.api.runner_delete_endpoint = '/api/{runner_type}/{runner_id}'
			# Answer 'n' to the confirmation prompt
			result = self.cli_runner.invoke(cli, ['r', 'rm', '-w', WORKSPACE, 'tasks/23'], input='n\n')
		self.assertNotEqual(result.exit_code, 0)
		self.assertTrue(self._exists('tasks', 23))


if __name__ == '__main__':
	unittest.main()
