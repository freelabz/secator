import os
import subprocess
import tempfile
import unittest
from unittest import mock

from secator.output_types import Error, Vulnerability
from secator.sources import clone_git_repo, is_git_url
from secator.tasks import gitleaks, trufflehog
from secator.utils_test import mock_subprocess_popen

REPO = 'git+https://github.com/octocat/Hello-World'


def fake_clone(url, folder):
	path = os.path.join(folder, 'Hello-World')
	os.makedirs(path)
	return path


class TestIsGitUrl(unittest.TestCase):

	def test_git_urls(self):
		for url in [REPO, 'git+http://git.lan/o/r.git', 'git@github.com:o/r.git', 'ssh://git@host/o/r', 'git://host/o/r']:
			self.assertTrue(is_git_url(url), url)

	def test_web_urls_and_other_values_are_not_git_urls(self):
		for value in [
			'https://github.com/octocat/Hello-World', 'https://example.com/config.git', 'ssh://host', 'git+https://host',
			'admin@example.com:8080', 'user@example.com', '/tmp/repo.git', None, 1,
		]:
			self.assertFalse(is_git_url(value), value)

	def test_url_with_credentials_is_refused(self):
		for url in ['git+https://user:token@github.com/o/r', 'git+https://token@git.lan/o/r', 'ssh://git:pass@host/o/r']:
			self.assertFalse(is_git_url(url), url)


class TestCloneGitRepo(unittest.TestCase):

	def test_shallow_clone_without_prompt(self):
		with mock.patch('secator.sources.subprocess.run') as run:
			path = clone_git_repo(f'{REPO}.git', '/dest')
		self.assertEqual(path, '/dest/Hello-World')
		args, kwargs = run.call_args
		url = 'https://github.com/octocat/Hello-World.git'
		self.assertEqual(args[0], ['git', 'clone', '--depth', '1', '--quiet', '--', url, path])
		self.assertEqual(kwargs['env']['GIT_TERMINAL_PROMPT'], '0')
		self.assertTrue(kwargs['check'])


class TestCloneGitInputs(unittest.TestCase):

	def setUp(self):
		self.reports = tempfile.mkdtemp()
		os.mkdir(f'{self.reports}/.inputs')
		self.opts = {'reports_folder': self.reports, 'print_target': False}

	def test_path_task_scans_clone_and_removes_it(self):
		with mock.patch('secator.runners.command.clone_git_repo', side_effect=fake_clone):
			task = gitleaks(REPO, **self.opts)
		path = task.inputs[0]
		self.assertTrue(task.inputs_valid)
		self.assertTrue(path.startswith(f'{self.reports}/.inputs/'))
		self.assertIn(path, task.cmd)
		self.assertNotIn(REPO, task.cmd)
		with mock_subprocess_popen(['']):
			list(task)
		self.assertFalse(os.path.exists(task.clone_folder))

	def test_clone_failure_is_an_error(self):
		error = subprocess.CalledProcessError(128, ['git'], stderr='repository not found')
		with mock.patch('secator.runners.command.clone_git_repo', side_effect=error):
			task = gitleaks(REPO, **self.opts)
		self.assertIn('repository not found', [r for r in task.results if isinstance(r, Error)][0].message)
		list(task)
		self.assertFalse(os.path.exists(task.clone_folder))

	def test_findings_point_at_the_git_url(self):
		with mock.patch('secator.runners.command.clone_git_repo', side_effect=fake_clone):
			task = gitleaks(REPO, **self.opts)
		path = task.inputs[0]
		item = Vulnerability(name='leak', matched_at=f'{path}/app.py', extra_data={'fingerprint': f'{path}/app.py:rule:1'})
		item = task._restore_git_urls(task, item)
		self.assertEqual(item.matched_at, f'{REPO}/app.py')
		self.assertEqual(item.extra_data['fingerprint'], f'{REPO}/app.py:rule:1')

	def test_chunked_run_clones_in_each_chunk(self):
		urls = [REPO, 'git@github.com:o/r.git']
		with mock.patch('secator.runners.command.IN_WORKER', True):
			with mock.patch('secator.runners.command.clone_git_repo') as clone:
				task = gitleaks(urls, caller='Task', **self.opts)
		self.assertTrue(task.needs_chunking(sync=False))
		self.assertEqual(task.inputs, urls)
		clone.assert_not_called()

	def test_url_task_and_dry_run_do_not_clone(self):
		with mock.patch('secator.runners.command.clone_git_repo') as clone:
			self.assertEqual(trufflehog(REPO, **self.opts).inputs, [REPO])
			self.assertEqual(gitleaks(REPO, dry_run=True, **self.opts).inputs, [REPO])
		clone.assert_not_called()


if __name__ == '__main__':
	unittest.main()
