import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secator.template_source import (
	TemplateSourceError, TemplateSourceRef, materialize_template_source,
	ref_from_dict, select_backend,
)


def _git(args, cwd):
	subprocess.run(['git', *args], cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class TestTemplateSourceRef(unittest.TestCase):

	def test_valid_ref(self):
		sha = 'a' * 40
		ref = TemplateSourceRef(name='php2shell', url='https://example.com/repo.git', sha=sha)
		self.assertEqual(ref.sha, sha)
		self.assertEqual(ref.name, 'php2shell')

	def test_rejects_non_sha_pin(self):
		for bad in ['main', 'v1.2.3', 'a' * 39, 'g' * 40, '']:
			with self.assertRaises(TemplateSourceError):
				TemplateSourceRef(name='x', url='https://e/r.git', sha=bad)

	def test_rejects_bad_name(self):
		for bad in ['../evil', 'UPPER', 'has space', '/abs', '']:
			with self.assertRaises(TemplateSourceError):
				TemplateSourceRef(name=bad, url='https://e/r.git', sha='a' * 40)

	def test_rejects_traversal_subdir(self):
		with self.assertRaises(TemplateSourceError):
			TemplateSourceRef(name='x', url='https://e/r.git', sha='a' * 40, subdir='../../etc')
		with self.assertRaises(TemplateSourceError):
			TemplateSourceRef(name='x', url='https://e/r.git', sha='a' * 40, subdir='/abs')

	def test_ref_from_dict_label_alias(self):
		ref = ref_from_dict({'label': 'php2shell', 'url': 'https://e/r.git', 'sha': 'b' * 40})
		self.assertEqual(ref.name, 'php2shell')


class TestBackendSelection(unittest.TestCase):

	def test_https_selects_git(self):
		ref = TemplateSourceRef(name='x', url='https://e/r.git', sha='a' * 40)
		from secator.template_source import git_backend
		self.assertIs(select_backend(ref), git_backend)

	def test_gs_without_addon_raises(self):
		ref = TemplateSourceRef(name='x', url='gs://bucket/prefix', sha='a' * 40)
		with mock.patch('secator.template_source.CONFIG.addons.gcs.bucket_name', ''):
			with self.assertRaises(TemplateSourceError):
				select_backend(ref)

	def test_gs_with_addon_selects_gcs(self):
		ref = TemplateSourceRef(name='x', url='gs://bucket/prefix', sha='a' * 40)
		from secator.template_source import gcs_backend
		with mock.patch('secator.template_source.CONFIG.addons.gcs.bucket_name', 'my-bucket'):
			self.assertIs(select_backend(ref), gcs_backend)


class TestMaterializeLocalFs(unittest.TestCase):
	"""Exercises the default git/local-fs backend end-to-end against a real local repo."""

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		# A throwaway "source repo" with one template file, committed twice.
		self.src = self.tmp / 'src'
		self.src.mkdir()
		_git(['init', '-q'], self.src)
		_git(['config', 'user.email', 't@t'], self.src)
		_git(['config', 'user.name', 't'], self.src)
		(self.src / 'tpl.yaml').write_text('id: test-template-v1\n')
		(self.src / 'sub').mkdir()
		(self.src / 'sub' / 'nested.yaml').write_text('id: nested\n')
		_git(['add', '-A'], self.src)
		_git(['commit', '-q', '-m', 'v1'], self.src)
		self.sha1 = subprocess.run(
			['git', 'rev-parse', 'HEAD'], cwd=self.src, stdout=subprocess.PIPE, text=True
		).stdout.strip()
		(self.src / 'tpl.yaml').write_text('id: test-template-v2\n')
		_git(['add', '-A'], self.src)
		_git(['commit', '-q', '-m', 'v2'], self.src)

		self.root = self.tmp / 'templates'
		self.root.mkdir()
		self.patcher = mock.patch('secator.template_source.CONFIG.dirs.templates', self.root)
		self.patcher.start()

	def tearDown(self):
		self.patcher.stop()
		shutil.rmtree(self.tmp, ignore_errors=True)

	def test_materialize_checks_out_pinned_sha(self):
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1)
		result = materialize_template_source(ref)
		self.assertTrue(result.refreshed)
		self.assertEqual(result.path, self.root / 'pinned')
		# Must be the FIRST commit's content, not the branch tip.
		self.assertEqual((result.path / 'tpl.yaml').read_text(), 'id: test-template-v1\n')

	def test_materialize_is_idempotent(self):
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1)
		materialize_template_source(ref)
		result2 = materialize_template_source(ref)
		self.assertFalse(result2.refreshed)

	def test_subdir_is_promoted_to_set_root(self):
		# A requested subdir IS the template set: only its contents are promoted to
		# the set root, so the templates root (scanned for external tasks/drivers at
		# import) never holds sibling non-template files from the source tree.
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1, subdir='sub')
		result = materialize_template_source(ref)
		self.assertEqual(result.path, self.root / 'pinned')
		self.assertTrue((result.path / 'nested.yaml').exists())
		# Top-level (non-subdir) files of the source must NOT leak into the set root.
		self.assertFalse((result.path / 'tpl.yaml').exists())

	def test_missing_subdir_raises(self):
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1, subdir='nope')
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_nonexistent_sha_raises(self):
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha='f' * 40)
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)


if __name__ == '__main__':
	unittest.main()
