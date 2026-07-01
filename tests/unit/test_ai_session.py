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


class TestTurnIdempotency(unittest.TestCase):
	"""C3: an acks_late redelivery of an already-completed turn must NOT replay
	_run_loop (no re-run tool actions, no re-billed tokens); a genuinely
	incomplete turn must still resume and run."""

	def _make_task(self, marker_docs, prior_docs, celery_id="turn-abc"):
		from secator.tasks.ai import ai

		task = ai.__new__(ai)
		task.interactive = "remote"
		task.session_id = "sess-123"
		task.session_name = ""
		task.mode = "chat"
		task.model = "gpt-4o"
		task.encryptor = None
		task.context = {"workspace_id": "ws1", "drivers": ["mongodb"], "celery_id": celery_id}
		task.context["ai_tokens"] = 0
		task.run_opts = {"prompt": "continue"}
		task._reports_folder = tempfile.mkdtemp(prefix="secator-test-")
		task.backend = MagicMock()
		task.debug = MagicMock()
		task.history = MagicMock()

		engine = MagicMock()
		engine.backend = MagicMock()
		engine.backend.name = "mongodb"

		def _search(query, limit=0):
			# The idempotency marker query is the only one keyed by turn_completed.
			if query.get("ai_type") == "turn_completed":
				return marker_docs
			if query.get("_type") == "ai":
				return prior_docs
			return []
		engine.search.side_effect = _search
		task._get_query_engine = MagicMock(return_value=engine)
		return task, engine

	def _drive(self, task):
		gen = task._maybe_resume_remote()
		restored = None
		try:
			while True:
				next(gen)
		except StopIteration as e:
			restored = e.value
		return restored

	def test_completed_turn_short_circuits_without_replay(self):
		"""A redelivery whose turn already has a completion marker short-circuits:
		_run_loop is not called and no tokens are billed."""
		task, engine = self._make_task(
			marker_docs=[{"ai_type": "turn_completed", "extra_data": {"turn_uuid": "turn-abc"}}],
			prior_docs=[{"ai_type": "prompt", "content": "hi"}],
		)
		task._run_loop = MagicMock(return_value=iter([]))

		with patch("secator.tasks.ai.restore_history_from_db") as mock_restore:
			restored = self._drive(task)

		self.assertTrue(restored)                       # turn handled (as a no-op)
		task._run_loop.assert_not_called()              # no tool actions replayed
		mock_restore.assert_not_called()                # didn't even rebuild/append
		self.assertEqual(task.context["ai_tokens"], 0)  # nothing re-billed

	@patch("secator.tasks.ai.restore_history_from_db")
	@patch("secator.tasks.ai.get_system_prompt", return_value="SYS")
	def test_incomplete_turn_still_resumes(self, mock_sys, mock_restore):
		"""No marker (a real mid-turn crash) → the turn resumes and runs _run_loop."""
		mock_restore.return_value = MagicMock(messages=[{"role": "system", "content": "SYS"}])
		task, engine = self._make_task(
			marker_docs=[],
			prior_docs=[{"ai_type": "prompt", "content": "hi"}],
		)
		task._detect_mode = MagicMock()
		task._run_loop = MagicMock(return_value=iter([]))
		task._mark_turn_completed = MagicMock()

		restored = self._drive(task)

		self.assertTrue(restored)
		mock_restore.assert_called_once()
		task._run_loop.assert_called_once()

	def test_mark_turn_completed_persists_marker(self):
		"""_mark_turn_completed persists exactly one turn_completed Ai stamped with
		the celery_id turn_uuid; it is a no-op off the remote channel."""
		from secator.output_types import Ai

		task, engine = self._make_task(marker_docs=[], prior_docs=[])
		persisted = []
		task.add_result = lambda item, **kw: persisted.append(item)

		task._mark_turn_completed()
		self.assertEqual(len(persisted), 1)
		marker = persisted[0]
		self.assertIsInstance(marker, Ai)
		self.assertEqual(marker.ai_type, "turn_completed")
		self.assertEqual(marker.extra_data.get("turn_uuid"), "turn-abc")
		self.assertEqual(marker.session_id, "sess-123")

		# Local channel: no marker persisted (idempotency is a remote concern).
		persisted.clear()
		task.interactive = "local"
		task._mark_turn_completed()
		self.assertEqual(persisted, [])


class TestFastDetectMode(unittest.TestCase):
	"""D4: the deterministic mode fast-path skips the intent LLM round-trip for
	unambiguous prompts, while ambiguous ones still fall back to the LLM."""

	def test_fast_detect_mode_pure(self):
		from secator.tasks.ai import fast_detect_mode
		self.assertEqual(fast_detect_mode("scan the target"), "attack")
		self.assertEqual(fast_detect_mode("summarize the findings"), "chat")
		self.assertEqual(fast_detect_mode(""), "chat")
		# exploit-ish → defer to LLM (no behavior change for those)
		self.assertIsNone(fast_detect_mode("write an exploit for this CVE-2024-1234"))
		# conflicting cues → ambiguous → defer to LLM
		self.assertIsNone(fast_detect_mode("scan and explain the results"))
		# no cues → ambiguous → defer to LLM
		self.assertIsNone(fast_detect_mode("please handle the situation"))

	def _make_task(self, prompt, mode=""):
		from secator.tasks.ai import ai
		task = ai.__new__(ai)
		task.mode = mode
		task.prompt = prompt
		task.intent_model = "intent-model"
		task.model = "main-model"
		task.api_base = None
		task.api_key = None
		task.max_iterations = 10
		task.is_subagent = False
		task.backend = MagicMock()
		task._reports_folder = tempfile.mkdtemp(prefix="secator-test-")
		task._account_usage = MagicMock()
		return task

	def _patches(self):
		return (
			patch("secator.tasks.ai.get_system_prompt", return_value="SYS"),
			patch("secator.tasks.ai.build_tool_schemas", return_value=[]),
			patch("secator.tasks.ai.get_mode_config", return_value={"max_iterations": 5}),
		)

	def test_fast_path_resolves_without_llm(self):
		"""Unambiguous prompt → mode set deterministically, call_llm untouched."""
		task = self._make_task("scan the target")
		p_sys, p_tools, p_cfg = self._patches()
		with p_sys, p_tools, p_cfg, patch("secator.tasks.ai.call_llm") as mock_llm:
			task._detect_mode()
		mock_llm.assert_not_called()
		self.assertEqual(task.mode, "attack")

	def test_ambiguous_falls_back_to_llm(self):
		"""Conflicting cues → the LLM classifier still runs and decides."""
		task = self._make_task("scan and explain the results")
		p_sys, p_tools, p_cfg = self._patches()
		with p_sys, p_tools, p_cfg, \
				patch("secator.tasks.ai.load_prompt", return_value="SELECT"), \
				patch("secator.tasks.ai.call_llm", return_value={"content": "chat", "usage": {}}) as mock_llm:
			task._detect_mode()
		mock_llm.assert_called_once()
		self.assertEqual(mock_llm.call_args[0][1], "intent-model")  # uses intent_model
		self.assertEqual(task.mode, "chat")

	def test_force_redetects_over_explicit_mode(self):
		"""force=True re-detects even when mode was explicitly set (fast-path applies)."""
		task = self._make_task("scan the target", mode="chat")
		p_sys, p_tools, p_cfg = self._patches()
		# Without force, explicit mode short-circuits (no detection, no LLM).
		with p_sys, p_tools, p_cfg, patch("secator.tasks.ai.call_llm") as mock_llm:
			task._detect_mode()
			self.assertEqual(task.mode, "chat")
			mock_llm.assert_not_called()
		# With force, detection runs again → fast-path flips to attack.
		p_sys, p_tools, p_cfg = self._patches()
		with p_sys, p_tools, p_cfg, patch("secator.tasks.ai.call_llm") as mock_llm:
			task._detect_mode(force=True)
			self.assertEqual(task.mode, "attack")
			mock_llm.assert_not_called()


if __name__ == "__main__":
	unittest.main()
