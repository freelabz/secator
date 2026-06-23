"""Tests for secator.ai.session restore_history_from_db + remote resume branch."""
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestRestoreHistoryFromDB(unittest.TestCase):
	"""Verify restore_history_from_db rebuilds an equivalent ChatHistory from Mongo docs."""

	def _docs(self):
		# Intentionally out of timestamp order to verify sorting.
		return [
			{"_type": "ai", "ai_type": "response", "content": "Hi, how can I help?", "_timestamp": 2},
			{"_type": "ai", "ai_type": "prompt", "content": "Hello", "_timestamp": 1},
			{"_type": "ai", "ai_type": "shell", "content": "nmap -p- host", "_timestamp": 3},
			{"_type": "ai", "ai_type": "prompt", "content": "Scan the target", "_timestamp": 4},
			{"_type": "ai", "ai_type": "follow_up", "content": "What next?", "_timestamp": 5},
			{"_type": "ai", "ai_type": "response", "content": "Found 2 open ports.", "_timestamp": 6},
		]

	def test_rebuilds_order_roles_and_system(self):
		from secator.ai.session import restore_history_from_db
		engine = MagicMock()
		engine.search.return_value = self._docs()

		history = restore_history_from_db(
			"session1", engine, model="gpt-4o", system_prompt="SYSTEM PROMPT")

		# Query was scoped to the session
		engine.search.assert_called_once_with({"_type": "ai", "session_id": "session1"})

		# System prompt set, conversation turns in timestamp order, non-turn docs skipped
		self.assertEqual(history.messages, [
			{"role": "system", "content": "SYSTEM PROMPT"},
			{"role": "user", "content": "Hello"},
			{"role": "assistant", "content": "Hi, how can I help?"},
			{"role": "user", "content": "Scan the target"},
			{"role": "assistant", "content": "Found 2 open ports."},
		])
		self.assertEqual(history.model, "gpt-4o")

	def test_no_prior_docs_returns_system_only(self):
		from secator.ai.session import restore_history_from_db
		engine = MagicMock()
		engine.search.return_value = []

		history = restore_history_from_db("s2", engine, system_prompt="SYS")
		self.assertEqual(history.messages, [{"role": "system", "content": "SYS"}])

	def test_no_system_prompt_yields_empty_when_no_docs(self):
		from secator.ai.session import restore_history_from_db
		engine = MagicMock()
		engine.search.return_value = []

		history = restore_history_from_db("s3", engine)
		self.assertEqual(history.messages, [])

	def test_empty_content_docs_skipped(self):
		from secator.ai.session import restore_history_from_db
		engine = MagicMock()
		engine.search.return_value = [
			{"ai_type": "prompt", "content": "", "_timestamp": 1},
			{"ai_type": "response", "content": "Real answer", "_timestamp": 2},
		]
		history = restore_history_from_db("s4", engine)
		self.assertEqual(history.messages, [{"role": "assistant", "content": "Real answer"}])

	def test_search_failure_returns_system_only(self):
		from secator.ai.session import restore_history_from_db
		engine = MagicMock()
		engine.search.side_effect = RuntimeError("backend down")

		history = restore_history_from_db("s5", engine, system_prompt="SYS")
		# Failure must not crash; returns just the system prompt
		self.assertEqual(history.messages, [{"role": "system", "content": "SYS"}])

	def test_encryptor_reencrypts_restored_turns(self):
		from secator.ai.session import restore_history_from_db
		engine = MagicMock()
		engine.search.return_value = [
			{"ai_type": "prompt", "content": "scan 10.0.0.1", "_timestamp": 1},
		]
		encryptor = MagicMock()
		encryptor.encrypt.side_effect = lambda t: f"ENC({t})"

		history = restore_history_from_db("s6", engine, encryptor=encryptor)
		self.assertEqual(history.messages, [{"role": "user", "content": "ENC(scan 10.0.0.1)"}])


class TestRemoteResumeBranch(unittest.TestCase):
	"""Verify the yielder remote-resume branch picks Mongo restore vs fresh start."""

	def _make_task(self, prior_docs, backend_name="mongodb"):
		from secator.tasks.ai import ai

		task = ai.__new__(ai)
		# Minimal attributes the branch touches
		task.interactive = "remote"
		task.session_id = "sess-123"
		task.session_name = ""
		task.mode = "chat"
		task.model = "gpt-4o"
		task.encryptor = None
		task.context = {"workspace_id": "ws1", "drivers": ["mongodb"]}
		task.run_opts = {"prompt": "Tell me about this workspace"}
		# An existing dir short-circuits the reports_folder property (no dir creation)
		task._reports_folder = tempfile.mkdtemp(prefix="secator-test-")
		task.backend = MagicMock()
		task.debug = MagicMock()
		task.history = MagicMock()

		# Stub query engine
		engine = MagicMock()
		engine.backend = MagicMock()
		engine.backend.name = backend_name

		def _search(query, limit=0):
			if query.get("_type") == "ai" and "session_id" in query:
				return prior_docs
			return []
		engine.search.side_effect = _search
		task._get_query_engine = MagicMock(return_value=engine)
		return task, engine

	def test_fresh_when_no_prior_docs(self):
		task, engine = self._make_task(prior_docs=[])
		# Generator return value is the StopIteration value.
		gen = task._maybe_resume_remote()
		restored = None
		try:
			while True:
				next(gen)
		except StopIteration as e:
			restored = e.value
		self.assertFalse(restored)

	@patch("secator.tasks.ai.restore_history_from_db")
	@patch("secator.tasks.ai.get_system_prompt", return_value="SYS")
	def test_restores_when_prior_docs(self, mock_sys, mock_restore):
		mock_history = MagicMock()
		mock_history.messages = [{"role": "system", "content": "SYS"}]
		mock_restore.return_value = mock_history

		task, engine = self._make_task(prior_docs=[{"ai_type": "prompt", "content": "hi"}])
		# Stub the heavy methods the branch calls
		task._detect_mode = MagicMock()
		task._run_loop = MagicMock(return_value=iter([]))

		gen = task._maybe_resume_remote()
		restored = None
		try:
			while True:
				next(gen)
		except StopIteration as e:
			restored = e.value

		self.assertTrue(restored)
		mock_restore.assert_called_once()
		# Restored from Mongo via the resolved query engine
		_, kwargs = mock_restore.call_args
		self.assertEqual(mock_restore.call_args[0][0], "sess-123")
		task._run_loop.assert_called_once()

	@patch("secator.tasks.ai.restore_history_from_db")
	@patch("secator.tasks.ai.get_system_prompt", return_value="SYS")
	def test_warns_on_non_mongo_backend(self, mock_sys, mock_restore):
		from secator.output_types import Warning as WarningType
		mock_restore.return_value = MagicMock(messages=[])

		task, engine = self._make_task(
			prior_docs=[{"ai_type": "prompt", "content": "hi"}], backend_name="local")
		task._detect_mode = MagicMock()
		task._run_loop = MagicMock(return_value=iter([]))

		items = []
		gen = task._maybe_resume_remote()
		try:
			while True:
				items.append(next(gen))
		except StopIteration:
			pass

		warnings = [i for i in items if isinstance(i, WarningType)]
		self.assertTrue(any("remote" in w.message for w in warnings))


if __name__ == "__main__":
	unittest.main()
