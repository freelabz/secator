"""Source resolution helpers (no network)."""
import unittest

from secator.sources import _repo_slug, _split_token, is_git_url


class TestSources(unittest.TestCase):

	def test_is_git_url(self):
		for ok in [
			'https://github.com/octocat/Hello-World',
			'https://github.com/octocat/Hello-World.git',
			'git@github.com:octocat/Hello-World.git',
			'https://gitlab.com/group/project',
			'https://ghe.acme.internal/org/repo.git',  # self-hosted via .git suffix
			'ssh://git@host/org/repo',
		]:
			self.assertTrue(is_git_url(ok), ok)
		for no in [
			'/tmp/code', '.', 'example.txt',
			'https://example.com/not-a-repo',  # unknown host, no .git
			'https://github.com/octocat',       # no repo part
			'http://10.0.0.1', 1234, None,
		]:
			self.assertFalse(is_git_url(no), no)

	def test_repo_slug(self):
		self.assertEqual(_repo_slug('https://github.com/octocat/Hello-World.git'), 'Hello-World')
		self.assertEqual(_repo_slug('https://gitlab.com/g/p/'), 'p')
		self.assertEqual(_repo_slug('git@github.com:o/weird name!.git'), 'weird_name_')

	def test_split_token_strips_from_clean_url(self):
		tokened, clean = _split_token('https://ghe.acme.internal/org/repo.git', 'SECRET')
		self.assertIn('SECRET@ghe.acme.internal', tokened)
		self.assertNotIn('SECRET', clean)  # the stored remote never carries the token
		self.assertEqual(clean, 'https://ghe.acme.internal/org/repo.git')

	def test_gcs_and_archive_detection(self):
		from secator.sources import is_gcs_url, is_archive_url
		assert is_gcs_url('gs://bucket/sources/x/app.zip')
		assert not is_gcs_url('https://github.com/a/b')
		assert is_archive_url('gs://bucket/x/app.zip')
		assert is_archive_url('App.TAR.GZ') and is_archive_url('x.tgz')
		assert not is_archive_url('gs://bucket/some/prefix')  # a bucket, not an archive
		assert not is_archive_url('x.py')


if __name__ == '__main__':
	unittest.main()
