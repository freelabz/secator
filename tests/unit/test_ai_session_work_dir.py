"""AI session-scoped work dir: files survive a task timeout by binding $work to the
conversation id on the shared ai_sessions volume (worker only; local CLI unchanged)."""

import os
import tempfile
import unittest
from unittest import mock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.tasks.ai import ai as AiTask
	from secator.config import CONFIG
	from secator.utils import sanitize_folder_name


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestResolveAiWorkDir(unittest.TestCase):
	"""_resolve_ai_work_dir picks the persistent session dir on a worker, else the reports folder."""

	def setUp(self):
		self.sessions = tempfile.mkdtemp()
		self.reports = os.path.join(tempfile.mkdtemp(), 'ws', 'tasks', '3')
		os.makedirs(self.reports, exist_ok=True)

	def _stub(self, session_id):
		# _resolve_ai_work_dir only touches self.session_id / self.reports_folder / self.debug —
		# call it unbound on a stub to avoid the heavy ai task __init__.
		s = mock.Mock()
		s.session_id = session_id
		s.reports_folder = self.reports
		s.debug = lambda *a, **k: None
		return s

	def _resolve(self, session_id, in_worker):
		with mock.patch('secator.definitions.IN_WORKER', in_worker), \
			mock.patch.object(CONFIG.dirs, 'ai_sessions', self.sessions):
			return AiTask._resolve_ai_work_dir(self._stub(session_id))

	def test_worker_uses_session_dir(self):
		work = self._resolve('conv-abc123', in_worker=True)
		self.assertEqual(work, os.path.join(self.sessions, sanitize_folder_name('conv-abc123')))
		self.assertTrue(os.path.isdir(work))

	def test_local_cli_uses_reports_folder(self):
		# Not a worker -> the filesystem persists anyway; keep the per-run reports folder.
		self.assertEqual(self._resolve('conv-abc123', in_worker=False), self.reports)

	def test_persists_across_timeout_for_same_conversation(self):
		# Task 1 clones a PoC, then "times out"; task 2 (same conversation id) maps to the SAME dir.
		work1 = self._resolve('conv-xyz', in_worker=True)
		poc = os.path.join(work1, '.outputs', 'poc')
		os.makedirs(poc, exist_ok=True)
		open(os.path.join(poc, 'exploit.py'), 'w').write('print("pwn")')
		# Task 2 has a *fresh* reports folder but the same conversation id.
		self.reports = os.path.join(tempfile.mkdtemp(), 'ws', 'tasks', '4')
		os.makedirs(self.reports, exist_ok=True)
		work2 = self._resolve('conv-xyz', in_worker=True)
		self.assertEqual(work1, work2)
		self.assertTrue(os.path.isfile(os.path.join(work2, '.outputs', 'poc', 'exploit.py')))

	def test_session_id_is_sanitized_no_traversal(self):
		work = self._resolve('../../etc/evil', in_worker=True)
		# The resolved dir stays under the sessions root (no escape).
		self.assertTrue(os.path.realpath(work).startswith(os.path.realpath(self.sessions)))

	def test_falls_back_when_sessions_dir_unwritable(self):
		with mock.patch('secator.definitions.IN_WORKER', True), \
			mock.patch.object(CONFIG.dirs, 'ai_sessions', '/proc/nonexistent/cannot-create'):
			work = AiTask._resolve_ai_work_dir(self._stub('c1'))
		self.assertEqual(work, self.reports)

	def test_no_session_id_uses_reports_folder(self):
		self.assertEqual(self._resolve('', in_worker=True), self.reports)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestConfigHasAiSessionsDir(unittest.TestCase):

	def test_ai_sessions_dir_defined(self):
		self.assertTrue(str(CONFIG.dirs.ai_sessions))  # non-empty, defaulted under the data dir


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestSandboxBindsSessionDir(unittest.TestCase):
	"""The isolated sandbox must mount the per-session work dir as /work (its cwd), so a bare
	`git clone` in an isolated shell persists to the shared conversation folder — not an
	ephemeral per-container volume. Regression for the isolated-container path."""

	def _run_ensure(self, context):
		from secator.ai import actions as A
		captured = {}

		def fake_run(argv, *a, **k):
			# capture the `docker run ...` argv; everything else (inspect/rm) is a no-op success
			r = mock.Mock()
			r.returncode = 0
			r.stdout = ""
			r.stderr = ""
			if isinstance(argv, list) and "run" in argv and "-d" in argv:
				captured["argv"] = argv
			return r

		ctx = A.ActionContext(targets=[], model='m', context=context, isolated=True)
		with mock.patch.object(A, "_sandbox_is_running", return_value=False), \
			mock.patch("subprocess.run", side_effect=fake_run):
			A._ensure_sandbox_container(ctx, context)
		return captured.get("argv", [])

	def _work_mount(self, argv):
		# the value following the FIRST "-v" is the /work mount
		for i, tok in enumerate(argv):
			if tok == "-v":
				return argv[i + 1]
		return ""

	def test_work_is_bound_to_session_dir(self):
		work = tempfile.mkdtemp()
		argv = self._run_ensure({"ai_work_dir": work, "session_id": "conv-1"})
		self.assertEqual(self._work_mount(argv), f"{work}:/work")
		self.assertIn("-w", argv)
		self.assertEqual(argv[argv.index("-w") + 1], "/work")

	def test_distinct_sessions_bind_distinct_dirs(self):
		w1, w2 = tempfile.mkdtemp(), tempfile.mkdtemp()
		self.assertNotEqual(w1, w2)
		m1 = self._work_mount(self._run_ensure({"ai_work_dir": w1, "session_id": "a"}))
		m2 = self._work_mount(self._run_ensure({"ai_work_dir": w2, "session_id": "b"}))
		self.assertEqual(m1, f"{w1}:/work")
		self.assertEqual(m2, f"{w2}:/work")
		self.assertNotEqual(m1, m2)

	def test_falls_back_to_named_volume_without_work_dir(self):
		# No ai_work_dir (e.g. no conversation id) -> the old per-container named volume.
		argv = self._run_ensure({"session_id": "x"})
		self.assertRegex(self._work_mount(argv), r":/work$")
		self.assertNotIn("/", self._work_mount(argv).split(":/work")[0])  # a volume name, not a path


if __name__ == '__main__':
	unittest.main()


if __name__ == '__main__':
	unittest.main()
