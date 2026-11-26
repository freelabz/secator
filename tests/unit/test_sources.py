import os
from base64 import b64encode
import subprocess
import tempfile
import unittest
from unittest import mock

from secator.output_types import Error, Vulnerability
from secator.sources import clone_git_repo, is_git_url
from secator.tasks import gitleaks, trufflehog
from secator.utils_test import mock_subprocess_popen

REPO = 'git+https://github.com/octocat/Hello-World'


def fake_clone(url, folder, token=None):
	path = os.path.join(folder, 'Hello-World')
	os.makedirs(f'{path}/.git')
	return path


class TestIsGitUrl(unittest.TestCase):

	def test_git_urls(self):
		for url in [
			REPO, 'git+http://git.lan/o/r', 'https://git.lan/o/r.git', 'http://git.lan/o/r.git',
			'git@github.com:o/r.git', 'ssh://git@host/o/r', 'git://host/o/r',
		]:
			self.assertTrue(is_git_url(url), url)

	def test_web_urls_and_other_transports_are_not_git_urls(self):
		for value in [
			'https://github.com/octocat/Hello-World', 'https://example.com/page', 'ssh://host', 'git+https://host',
			'file:///srv/repo.git', 'ext::sh -c id', 'admin@example.com:8080', 'user@example.com', '/tmp/repo.git',
			None, 1,
		]:
			self.assertFalse(is_git_url(value), value)

	def test_url_with_credentials_is_refused(self):
		for url in ['git+https://user:token@github.com/o/r', 'https://token@git.lan/o/r.git', 'ssh://git:pass@host/o/r']:
			self.assertFalse(is_git_url(url), url)


class TestCloneGitRepo(unittest.TestCase):

	def clone(self, url, token=None):
		with mock.patch('secator.sources.subprocess.run') as run:
			path = clone_git_repo(url, '/dest', token=token)
		args, kwargs = run.call_args
		env = kwargs['env']
		config = {env[f'GIT_CONFIG_KEY_{i}']: env[f'GIT_CONFIG_VALUE_{i}'] for i in range(int(env['GIT_CONFIG_COUNT']))}
		return path, args[0], env, config

	def test_shallow_clone_with_safe_transports(self):
		path, argv, env, config = self.clone(f'{REPO}.git')
		self.assertEqual(path, '/dest/Hello-World')
		url = 'https://github.com/octocat/Hello-World.git'
		self.assertEqual(argv, ['git', 'clone', '--depth', '1', '--quiet', '--', url, path])
		self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')
		self.assertEqual(env['GIT_ALLOW_PROTOCOL'], 'http:https:ssh:git')
		self.assertEqual(config, {'http.followRedirects': 'false'})

	def test_token_is_an_https_header_scoped_to_the_origin(self):
		_, argv, _, config = self.clone('https://git.lan:8443/o/r.git', token='S3CR3T')
		header = config['http.https://git.lan:8443/.extraHeader']
		self.assertEqual(header, 'Authorization: Basic ' + b64encode(b'x-access-token:S3CR3T').decode())
		self.assertNotIn('S3CR3T', ' '.join(argv))
		_, _, _, config = self.clone('https://git.lan/o/r.git', token='oauth2:S3CR3T')
		header = config['http.https://git.lan/.extraHeader']
		self.assertEqual(header, 'Authorization: Basic ' + b64encode(b'oauth2:S3CR3T').decode())

	def test_token_is_never_sent_over_other_transports(self):
		for url in ['http://git.lan/o/r.git', 'git@github.com:o/r.git', 'ssh://git@host/o/r', 'git://host/o/r']:
			_, _, _, config = self.clone(url, token='S3CR3T')
			self.assertEqual(config, {'http.followRedirects': 'false'}, url)

	def test_file_transport_is_refused_by_git(self):
		source = tempfile.mkdtemp()
		subprocess.run(['git', 'init', '-q', source], check=True)
		subprocess.run(['git', '-C', source, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'x'], check=True)  # noqa: E501
		with self.assertRaises(subprocess.CalledProcessError):
			clone_git_repo(f'file://{source}', tempfile.mkdtemp())


class TestCloneGitInputs(unittest.TestCase):

	def setUp(self):
		self.reports = tempfile.mkdtemp()
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
		item = Vulnerability(name='leak', matched_at=f'{path}/app.py', extra_data={'locations': [{'path': f'{path}/app.py'}]})
		item = task._restore_git_urls(task, item)
		self.assertEqual(item.matched_at, f'{REPO}/app.py')
		self.assertEqual(item.extra_data['locations'], [{'path': f'{REPO}/app.py'}])

	def test_chunked_run_clones_in_each_chunk(self):
		urls = [REPO, 'git@github.com:o/r.git']
		os.mkdir(f'{self.reports}/.inputs')  # the multi-input file goes there
		with mock.patch('secator.runners.command.IN_WORKER', True):
			with mock.patch('secator.runners.command.clone_git_repo') as clone:
				task = gitleaks(urls, caller='Task', **self.opts)
		self.assertTrue(task.needs_chunking(sync=False))
		self.assertEqual(task.inputs, urls)
		clone.assert_not_called()

	def test_url_task_gets_the_clone(self):
		with mock.patch('secator.runners.command.clone_git_repo', side_effect=fake_clone):
			task = trufflehog(REPO, **self.opts)
		self.assertTrue(task.inputs[0].startswith(f'{self.reports}/.inputs/'))
		self.assertIn('git file://', task.cmd)

	def test_git_token_is_used_and_redacted(self):
		with mock.patch('secator.runners.command.clone_git_repo', side_effect=fake_clone) as clone:
			task = gitleaks(REPO, git_token='S3CR3T', **self.opts)
		self.assertEqual(clone.call_args.kwargs['token'], 'S3CR3T')
		self.assertNotIn('S3CR3T', str(task.toDict()))
		self.assertNotIn('S3CR3T', task.cmd)

	def test_dry_run_does_not_clone(self):
		with mock.patch('secator.runners.command.clone_git_repo') as clone:
			self.assertEqual(gitleaks(REPO, dry_run=True, **self.opts).inputs, [REPO])
		clone.assert_not_called()


if __name__ == '__main__':
	unittest.main()
