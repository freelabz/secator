"""AI file model (secator #1452): $work is always the per-run reports folder; $data is the
persistent per-conversation dir ~/.secator/ai/<session_id> (survives a task timeout / --resume).
No worker-vs-local branching. Plus the local session index that backs --resume."""

import os
import tempfile
import unittest
from unittest import mock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.tasks.ai import ai as AiTask
	from secator.config import CONFIG
	from secator.utils import sanitize_folder_name
	from secator.ai import session as ai_session
	from secator.ai.prompts import get_system_prompt
	from secator.ai.guardrails import PermissionEngine


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestSetAiDataDir(unittest.TestCase):
	"""_set_ai_data_dir maps the conversation to ~/.secator/ai/<session_id>, unconditionally."""

	def _stub(self, session_id):
		s = mock.Mock()
		s.session_id = session_id
		s.context = {}
		s.permission_engine = None
		s.debug = lambda *a, **k: None
		return s

	def test_data_dir_is_under_ai_base_keyed_by_session(self):
		s = self._stub("conv-abc")
		AiTask._set_ai_data_dir(s)
		expected = os.path.join(str(CONFIG.dirs.ai), sanitize_folder_name("conv-abc"))
		self.assertEqual(s.ai_data_dir, expected)
		self.assertTrue(os.path.isdir(s.ai_data_dir))            # created
		self.assertEqual(s.context["ai_data_dir"], s.ai_data_dir)  # propagated to context

	def test_session_id_sanitized_no_traversal(self):
		s = self._stub("../../etc/evil")
		AiTask._set_ai_data_dir(s)
		# the dir stays under the ai base — no escaping via traversal
		self.assertTrue(os.path.realpath(s.ai_data_dir).startswith(os.path.realpath(str(CONFIG.dirs.ai))))

	def test_refreshes_permission_engine_ai_data(self):
		s = self._stub("conv-xyz")
		s.permission_engine = mock.Mock()
		AiTask._set_ai_data_dir(s)
		self.assertEqual(s.permission_engine.ai_data, s.ai_data_dir)

	def test_recompute_after_resume_adopts_new_session(self):
		s = self._stub("first")
		AiTask._set_ai_data_dir(s)
		first = s.ai_data_dir
		s.session_id = "resumed"                 # --resume adopts a prior id
		AiTask._set_ai_data_dir(s)
		self.assertNotEqual(s.ai_data_dir, first)
		self.assertTrue(s.ai_data_dir.endswith(sanitize_folder_name("resumed")))


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestPromptAndPermissions(unittest.TestCase):

	def test_prompt_substitutes_data_path(self):
		out = get_system_prompt("chat", workspace_path="/reports/run", data_path="/home/x/.secator/ai/s1")
		self.assertIn("/home/x/.secator/ai/s1", out)
		self.assertNotIn("$data_path", out)

	def test_ai_data_permission_rules_allow_the_data_dir(self):
		# The shell path layer (detect_paths_with_access -> _check_value) gates run_shell file access;
		# the {ai_data} rules must allow read+write anywhere under the persistent data dir, incl. nested
		# clones like $data_path/poc/exploit.py.
		data = "/home/x/.secator/ai/s1"
		eng = PermissionEngine(
			{"allow": ["read({ai_data}/*,{ai_data})", "write({ai_data}/*,{ai_data})"], "deny": [], "ask": []},
			ai_data=data)
		self.assertEqual(eng._check_value("write", f"{data}/poc/exploit.py").decision, "allow")
		self.assertEqual(eng._check_value("read", f"{data}/notes.md").decision, "allow")
		self.assertEqual(eng._check_value("write", data).decision, "allow")  # the dir itself


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestSandboxBindsDataDir(unittest.TestCase):
	"""The isolated sandbox binds the persistent data dir at its host path so $data_path resolves
	inside the container and survives a timeout — no more per-container ephemeral swap."""

	def _docker_run_argv(self, context):
		from secator.ai import actions as A
		captured = {}

		def fake_run(argv, *a, **k):
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

	def test_data_dir_bound_at_same_host_path(self):
		data = tempfile.mkdtemp()
		argv = self._docker_run_argv({"ai_data_dir": data})
		self.assertIn(f"{data}:{data}", argv)   # bound at the same path -> $data_path resolves
		self.assertIn(f"{data}", "".join(argv))

	def test_no_data_dir_no_extra_bind(self):
		argv = self._docker_run_argv({})
		# still creates the sandbox (reports bind + named /work volume), just no data bind
		vs = [argv[i + 1] for i, t in enumerate(argv) if t == "-v"]
		self.assertTrue(any(v.endswith(":/work") for v in vs))


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestSessionIndex(unittest.TestCase):
	"""save_history writes to the data dir; the session index backs --resume (list_sessions)."""

	def _with_ai_base(self, base):
		# NOTE: do NOT mock.patch.object(CONFIG.dirs, "ai", ...) — CONFIG.dirs is DotMap-backed and
		# the patch restores a bogus value (the parent Config), corrupting CONFIG.dirs.ai for later
		# tests. Save/restore by hand instead.
		import contextlib

		@contextlib.contextmanager
		def _ctx():
			prev = CONFIG.dirs.ai
			CONFIG.dirs.ai = base
			try:
				yield
			finally:
				CONFIG.dirs.ai = prev
		return _ctx()

	def test_save_history_writes_to_data_dir(self):
		data = tempfile.mkdtemp()
		hist = mock.Mock()
		hist.messages = [{"role": "user", "content": "hi"}]
		ai_session.save_history(hist, data)
		self.assertTrue(os.path.isfile(os.path.join(data, "history.json")))

	def test_index_roundtrip_and_list(self):
		base = tempfile.mkdtemp()
		with self._with_ai_base(base):
			data = os.path.join(base, "conv-1")
			os.makedirs(data, exist_ok=True)
			hist = mock.Mock()
			hist.messages = [{"role": "user", "content": "scan example.com"}]
			ai_session.save_history(hist, data)
			ai_session.update_session_index("conv-1", data, name="my scan",
			                                prompt="scan example.com", targets=["example.com"])
			sessions = ai_session.list_sessions()
		self.assertEqual(len(sessions), 1)
		s = sessions[0]
		self.assertEqual(s["session_id"], "conv-1")
		self.assertEqual(s["prompt"], "scan example.com")
		self.assertEqual(s["history_path"], os.path.join(data, "history.json"))

	def test_list_skips_entries_without_history(self):
		base = tempfile.mkdtemp()
		with self._with_ai_base(base):
			ai_session.update_session_index("gone", os.path.join(base, "gone"))  # no history.json written
			self.assertEqual(ai_session.list_sessions(), [])


if __name__ == '__main__':
	unittest.main()
