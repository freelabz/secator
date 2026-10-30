import os
import shutil
import subprocess
import tarfile
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


class TestEnvIntParsing(unittest.TestCase):
	"""A garbage size-cap override must surface as a clean TemplateSourceError."""

	def test_non_integer_env_raises(self):
		from secator import template_source as ts
		with mock.patch.dict(os.environ, {'SECATOR_TEMPLATE_SET_MAX_BYTES': 'lots'}):
			with self.assertRaises(TemplateSourceError):
				ts._env_int('SECATOR_TEMPLATE_SET_MAX_BYTES', 1)

	def test_non_positive_env_raises(self):
		from secator import template_source as ts
		with mock.patch.dict(os.environ, {'SECATOR_TEMPLATE_SET_MAX_BYTES': '0'}):
			with self.assertRaises(TemplateSourceError):
				ts._env_int('SECATOR_TEMPLATE_SET_MAX_BYTES', 1)

	def test_valid_env_parsed(self):
		from secator import template_source as ts
		with mock.patch.dict(os.environ, {'SECATOR_TEMPLATE_SET_MAX_BYTES': '2048'}):
			self.assertEqual(ts._env_int('SECATOR_TEMPLATE_SET_MAX_BYTES', 1), 2048)


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
		# These tests exercise backend *mechanics* by cloning a throwaway LOCAL repo,
		# which git treats as the `file` transport — hardened off in production (where
		# clone URLs are https-only, enforced by the API scheme allowlist). Re-enable the
		# file transport just for these mechanics tests. The F1 block is proven separately
		# in TestGitTransportHardening.
		self.hardening = mock.patch(
			'secator.template_source._GIT_TRANSPORT_HARDENING',
			['-c', 'protocol.file.allow=always'],
		)
		self.hardening.start()
		self.allowproto = mock.patch(
			'secator.template_source._GIT_ALLOW_PROTOCOL', 'file:https:http:ssh:git'
		)
		self.allowproto.start()

	def tearDown(self):
		self.allowproto.stop()
		self.hardening.stop()
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
		first = materialize_template_source(ref)
		result2 = materialize_template_source(ref)
		self.assertFalse(result2.refreshed)
		# Reuse must return the same path and preserve the pinned contents.
		self.assertEqual(result2.path, first.path)
		self.assertEqual((result2.path / 'tpl.yaml').read_text(), 'id: test-template-v1\n')

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

	def test_same_sha_different_subdir_re_materializes(self):
		# Reuse must key on subdir too: same name+SHA but a different subdir promotes
		# different content, so a cache hit on SHA alone would serve the wrong tree.
		whole = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1)
		r1 = materialize_template_source(whole)
		self.assertTrue(r1.refreshed)
		self.assertTrue((r1.path / 'tpl.yaml').exists())
		# Now request the 'sub' subdir at the SAME sha — must re-materialize, not reuse.
		subref = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1, subdir='sub')
		r2 = materialize_template_source(subref)
		self.assertTrue(r2.refreshed)
		self.assertTrue((r2.path / 'nested.yaml').exists())
		self.assertFalse((r2.path / 'tpl.yaml').exists())
		# Re-requesting the subdir ref now reuses (same sha + subdir).
		r3 = materialize_template_source(subref)
		self.assertFalse(r3.refreshed)

	def test_missing_subdir_raises(self):
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=self.sha1, subdir='nope')
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_nonexistent_sha_raises(self):
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha='f' * 40)
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_rejects_py_file_in_tree(self):
		# A template set carrying a `.py` would be exec'd by the task/driver loader at
		# import time (worker RCE). Materialization must refuse it.
		(self.src / 'evil.py').write_text('import os; os.system("id")\n')
		_git(['add', '-A'], self.src)
		_git(['commit', '-q', '-m', 'add py'], self.src)
		sha = subprocess.run(
			['git', 'rev-parse', 'HEAD'], cwd=self.src, stdout=subprocess.PIPE, text=True
		).stdout.strip()
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=sha)
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_rejects_symlink_in_tree(self):
		os.symlink('/etc/passwd', self.src / 'link')
		_git(['add', '-A'], self.src)
		_git(['commit', '-q', '-m', 'add symlink'], self.src)
		sha = subprocess.run(
			['git', 'rev-parse', 'HEAD'], cwd=self.src, stdout=subprocess.PIPE, text=True
		).stdout.strip()
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=sha)
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_rejects_symlink_subdir_escape(self):
		# A symlinked subdir that points outside the staged tree must not be promoted.
		outside = self.tmp / 'outside'
		outside.mkdir()
		(outside / 'secret.yaml').write_text('id: secret\n')
		os.symlink(outside, self.src / 'linkdir')
		_git(['add', '-A'], self.src)
		_git(['commit', '-q', '-m', 'add symlink dir'], self.src)
		sha = subprocess.run(
			['git', 'rev-parse', 'HEAD'], cwd=self.src, stdout=subprocess.PIPE, text=True
		).stdout.strip()
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=sha, subdir='linkdir')
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_rejects_oversized_tree(self):
		big = self.src / 'big.yaml'
		big.write_bytes(b'a' * (2 * 1024 * 1024))
		_git(['add', '-A'], self.src)
		_git(['commit', '-q', '-m', 'big'], self.src)
		sha = subprocess.run(
			['git', 'rev-parse', 'HEAD'], cwd=self.src, stdout=subprocess.PIPE, text=True
		).stdout.strip()
		ref = TemplateSourceRef(name='pinned', url=str(self.src), sha=sha)
		with mock.patch('secator.template_source._MAX_TEMPLATE_SET_BYTES', 1024):
			with self.assertRaises(TemplateSourceError):
				materialize_template_source(ref)


class TestGitTransportHardening(unittest.TestCase):
	"""The default git backend must refuse ext::/file:// transports (RCE/LFI)."""

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())
		self.root = self.tmp / 'templates'
		self.root.mkdir()
		self.patcher = mock.patch('secator.template_source.CONFIG.dirs.templates', self.root)
		self.patcher.start()

	def tearDown(self):
		self.patcher.stop()
		shutil.rmtree(self.tmp, ignore_errors=True)

	def test_ext_transport_rejected(self):
		marker = self.tmp / 'pwned'
		ref = TemplateSourceRef(
			name='pwn', url=f"ext::sh -c 'touch {marker}'", sha='a' * 40,
		)
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)
		self.assertFalse(marker.exists(), 'ext:: transport executed a command (RCE)')

	def test_file_transport_rejected(self):
		# file:// (and bare local path treated as file transport) must be blocked.
		donor = self.tmp / 'donor'
		donor.mkdir()
		ref = TemplateSourceRef(name='pwn', url=f'file://{donor}', sha='a' * 40)
		with self.assertRaises(TemplateSourceError):
			materialize_template_source(ref)

	def test_git_timeout_surfaces_clean_error(self):
		# A hung git invocation must raise a clean TemplateSourceError, not hang the worker.
		from secator import template_source as ts
		with mock.patch.object(
			ts.subprocess, 'run',
			side_effect=subprocess.TimeoutExpired(cmd='git', timeout=ts._GIT_TIMEOUT),
		):
			with self.assertRaises(TemplateSourceError) as ctx:
				ts._run_git(['clone', 'https://example.test/x.git'])
		self.assertIn('timed out', str(ctx.exception))


class TestTarballGuards(unittest.TestCase):
	"""gcs_backend tarball extraction must reject link members, traversal, .py, bombs."""

	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())

	def tearDown(self):
		shutil.rmtree(self.tmp, ignore_errors=True)

	def _run_gcs_backend(self, tarball: Path, name='x'):
		import sys
		import types
		from secator import template_source as ts
		ref = TemplateSourceRef(name=name, url='gs://bucket/prefix', sha='a' * 40)
		dest = self.tmp / 'dest'

		def fake_download(bucket, blob_name, out_path):
			shutil.copy(tarball, out_path)

		# `gcs_backend` does `from secator.hooks.gcs import download_blob` at call
		# time. The real module imports `google.cloud.storage`, which is only present
		# when the GCS addon is installed (absent in the unit-test env), so we inject
		# a stub module instead of patching the attribute on the (unimportable) real one.
		stub = types.ModuleType('secator.hooks.gcs')
		stub.download_blob = fake_download
		with mock.patch.dict(sys.modules, {'secator.hooks.gcs': stub}):
			ts.gcs_backend(ref, dest)

	def test_symlink_member_rejected(self):
		tb = self.tmp / 't.tar.gz'
		with tarfile.open(tb, 'w:gz') as tf:
			data = self.tmp / 'ok.yaml'
			data.write_text('id: ok\n')
			tf.add(data, arcname='ok.yaml')
			info = tarfile.TarInfo('link')
			info.type = tarfile.SYMTYPE
			info.linkname = '/etc/passwd'
			tf.addfile(info)
		with self.assertRaises(TemplateSourceError):
			self._run_gcs_backend(tb)

	def test_py_member_rejected(self):
		tb = self.tmp / 't.tar.gz'
		with tarfile.open(tb, 'w:gz') as tf:
			evil = self.tmp / 'evil.py'
			evil.write_text('x = 1\n')
			tf.add(evil, arcname='evil.py')
		with self.assertRaises(TemplateSourceError):
			self._run_gcs_backend(tb)

	def test_traversal_member_rejected(self):
		tb = self.tmp / 't.tar.gz'
		with tarfile.open(tb, 'w:gz') as tf:
			data = self.tmp / 'ok.yaml'
			data.write_text('id: ok\n')
			tf.add(data, arcname='../escape.yaml')
		with self.assertRaises(TemplateSourceError):
			self._run_gcs_backend(tb)

	def test_oversized_tarball_rejected(self):
		tb = self.tmp / 't.tar.gz'
		big = self.tmp / 'big.yaml'
		big.write_bytes(b'a' * (2 * 1024 * 1024))
		with tarfile.open(tb, 'w:gz') as tf:
			tf.add(big, arcname='big.yaml')
		from secator import template_source as ts
		with mock.patch.object(ts, '_MAX_TEMPLATE_SET_BYTES', 1024):
			with self.assertRaises(TemplateSourceError):
				self._run_gcs_backend(tb)

	def test_too_many_members_rejected(self):
		tb = self.tmp / 't.tar.gz'
		data = self.tmp / 'ok.yaml'
		data.write_text('id: ok\n')
		with tarfile.open(tb, 'w:gz') as tf:
			for i in range(5):
				tf.add(data, arcname=f'ok{i}.yaml')
		from secator import template_source as ts
		with mock.patch.object(ts, '_MAX_TEMPLATE_SET_MEMBERS', 3):
			with self.assertRaises(TemplateSourceError):
				self._run_gcs_backend(tb)

	def test_non_regular_member_rejected(self):
		tb = self.tmp / 't.tar.gz'
		with tarfile.open(tb, 'w:gz') as tf:
			info = tarfile.TarInfo('dev')
			info.type = tarfile.CHRTYPE  # character device — not a plain file/dir
			tf.addfile(info)
		with self.assertRaises(TemplateSourceError):
			self._run_gcs_backend(tb)


if __name__ == '__main__':
	unittest.main()
