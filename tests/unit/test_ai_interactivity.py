"""Tests for secator.ai.interactivity module."""
import unittest
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)


class TestInteractivityBackendBase(unittest.TestCase):
	"""Verify base class interface."""

	def test_base_ask_user_raises(self):
		from secator.ai.interactivity import InteractivityBackend
		backend = InteractivityBackend()
		with self.assertRaises(NotImplementedError):
			backend.ask_user("question", [], "session1")

	def test_base_get_excluded_tools(self):
		from secator.ai.interactivity import InteractivityBackend
		backend = InteractivityBackend()
		self.assertEqual(backend.get_excluded_tools(), set())

	def test_base_get_extra_tools(self):
		from secator.ai.interactivity import InteractivityBackend
		backend = InteractivityBackend()
		self.assertEqual(backend.get_extra_tools(), [])


class TestCLIBackend(unittest.TestCase):
	"""Verify CLIBackend behavior."""

	def test_excluded_tools(self):
		from secator.ai.interactivity import CLIBackend
		backend = CLIBackend()
		self.assertEqual(backend.get_excluded_tools(), {"stop"})

	def test_extra_tools_empty(self):
		from secator.ai.interactivity import CLIBackend
		backend = CLIBackend()
		self.assertEqual(backend.get_extra_tools(), [])


class TestAutoBackend(unittest.TestCase):
	"""Verify AutoBackend behavior."""

	def test_excluded_tools(self):
		from secator.ai.interactivity import AutoBackend
		backend = AutoBackend()
		self.assertEqual(backend.get_excluded_tools(), {"follow_up"})

	def test_extra_tools_has_stop(self):
		from secator.ai.interactivity import AutoBackend
		backend = AutoBackend()
		extra = backend.get_extra_tools()
		self.assertEqual(len(extra), 1)
		self.assertEqual(extra[0]["function"]["name"], "stop")

	def test_ask_user_returns_none(self):
		"""AutoBackend.ask_user returns None — no user to ask."""
		from secator.ai.interactivity import AutoBackend
		backend = AutoBackend()
		result = backend.ask_user("q", [], "s1")
		self.assertIsNone(result)


class TestRemoteBackend(unittest.TestCase):
	"""Verify RemoteBackend behavior."""

	def test_excluded_tools(self):
		from secator.ai.interactivity import RemoteBackend
		backend = RemoteBackend(timeout=60, query_engine=MagicMock())
		self.assertEqual(backend.get_excluded_tools(), {"stop"})

	def test_extra_tools_empty(self):
		from secator.ai.interactivity import RemoteBackend
		backend = RemoteBackend(timeout=60, query_engine=MagicMock())
		self.assertEqual(backend.get_extra_tools(), [])

	def test_ask_user_returns_answer_on_found(self):
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = [{"answer": "option A"}]
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		result = backend.ask_user("What next?", ["A", "B"], "session1")

		self.assertIsNotNone(result)
		self.assertEqual(result["answer"], "option A")

	@patch('secator.ai.interactivity.sleep')
	def test_ask_user_polls_until_timeout(self, mock_sleep):
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = []  # never answered
		mock_engine.update = MagicMock()
		backend = RemoteBackend(timeout=10, query_engine=mock_engine, poll_interval=5)

		result = backend.ask_user("What next?", [], "session1")

		self.assertIsNone(result)
		# Should have polled twice (0s, 5s) then timed out at 10s
		self.assertEqual(mock_sleep.call_count, 2)
		# Should have called update to set timed_out
		mock_engine.update.assert_called_once()

	def test_poll_scopes_query_to_prompt_uuid(self):
		"""The poll must correlate on the specific prompt's uuid.

		Regression test for the infinite-respawn loop: without scoping on
		prompt_uuid, a stale answered follow_up from a prior turn resolves the
		current wait immediately, the worker re-injects that old answer as a new
		prompt and re-runs the turn forever. The query MUST include
		extra_data.prompt_uuid so only THIS prompt's own answer resolves it.
		"""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = [{"answer": "the right answer"}]
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		result = backend.ask_user("What next?", [], "session1", prompt_uuid="abc-123")

		self.assertEqual(result["answer"], "the right answer")
		# The search query must be scoped to this prompt's uuid (else a stale
		# answered follow_up from a prior turn would match -> loop).
		search_query = mock_engine.search.call_args[0][0]
		self.assertEqual(search_query.get("extra_data.prompt_uuid"), "abc-123")
		self.assertEqual(search_query.get("status"), "answered")

	@patch('secator.ai.interactivity.sleep')
	def test_timeout_update_scoped_to_prompt_uuid(self, mock_sleep):
		"""On timeout, only THIS prompt's pending doc is flipped to timed_out."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = []  # never answered
		mock_engine.update = MagicMock()
		backend = RemoteBackend(timeout=5, query_engine=mock_engine, poll_interval=5)

		result = backend.ask_user("What next?", [], "session1", prompt_uuid="abc-123")

		self.assertIsNone(result)
		mock_engine.update.assert_called_once()
		update_query = mock_engine.update.call_args[0][0]
		self.assertEqual(update_query.get("extra_data.prompt_uuid"), "abc-123")
		self.assertEqual(update_query.get("status"), "pending")

	def test_build_pending_prompt_stamps_permission_prompt_uuid(self):
		"""A permission pending doc carries its prompt_uuid in extra_data."""
		from secator.ai.interactivity import RemoteBackend
		backend = RemoteBackend(timeout=60, query_engine=MagicMock())
		item = backend.build_pending_prompt(
			"Shell `nmap` requires approval", ["allow", "deny"], "session1",
			prompt_type="permission", permission_type="shell", value="nmap",
			prompt_uuid="uuid-shell",
		)
		self.assertEqual(item.extra_data.get("prompt_uuid"), "uuid-shell")
		self.assertEqual(item.extra_data.get("permission_type"), "shell")
		self.assertEqual(item.ai_type, "permission")
		self.assertEqual(item.status, "pending")

	@patch('secator.ai.interactivity.sleep')
	def test_later_permission_layer_does_not_resolve_from_earlier_allow(self, mock_sleep):
		"""H7: a later guardrail layer must not auto-resolve from an earlier 'allow'."""
		from secator.ai.interactivity import RemoteBackend

		# Fake "DB": one answered doc from the FIRST (shell) layer only.
		answered_db = [{
			"_type": "ai", "ai_type": "permission", "status": "answered",
			"_context": {"session_id": "session1"},
			"extra_data": {"prompt_uuid": "uuid-shell"},
			"answer": "allow", "_timestamp": 100.0,
		}]

		def fake_search(query, *args, **kwargs):
			# Honor prompt_uuid scoping like a real backend would.
			want_uuid = query.get("extra_data.prompt_uuid")
			out = []
			for d in answered_db:
				if d.get("status") != query.get("status"):
					continue
				if want_uuid is not None and d["extra_data"].get("prompt_uuid") != want_uuid:
					continue
				out.append(d)
			return out

		mock_engine = MagicMock()
		mock_engine.search.side_effect = fake_search
		backend = RemoteBackend(timeout=5, query_engine=mock_engine, poll_interval=5)

		# First (shell) layer resolves to its own answered "allow".
		first = backend._poll_for_answer("session1", "permission", prompt_uuid="uuid-shell")
		self.assertEqual(first, "allow")

		# Second (target) layer must NOT pick up the shell layer's "allow".
		second = backend._poll_for_answer("session1", "permission", prompt_uuid="uuid-target")
		self.assertIsNone(second)

	def test_poll_returns_newest_answered_doc(self):
		"""Defense in depth: resolve against the NEWEST answered doc by _timestamp."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = [
			{"answer": "stale", "_timestamp": 100.0},
			{"answer": "fresh", "_timestamp": 200.0},
		]
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)
		result = backend._poll_for_answer("session1", "permission", prompt_uuid="abc-123")
		self.assertEqual(result, "fresh")

	@patch('secator.ai.interactivity.sleep')
	def test_ask_user_returns_on_second_poll(self, mock_sleep):
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		# Query-aware: the follow-up answer poll (ai_type=="follow_up") returns the
		# answer on the second call; the interleaved steer poll (ai_type=="steer")
		# always returns nothing — so the steer-break never fires here.
		answer_calls = {"n": 0}

		def search(query, limit=1):
			if query.get("ai_type") == "steer":
				return []
			answer_calls["n"] += 1
			return [] if answer_calls["n"] == 1 else [{"answer": "option B"}]

		mock_engine.search.side_effect = search
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=5)

		result = backend.ask_user("What next?", [], "session1")

		self.assertIsNotNone(result)
		self.assertEqual(result["answer"], "option B")
		self.assertEqual(mock_sleep.call_count, 1)

	@patch('secator.ai.interactivity.sleep')
	def test_answer_in_final_window_is_not_lost_to_timeout(self, mock_sleep):
		"""M10: an answer landing in the last sleep window is returned, not lost.

		The poll loop sees only 'pending' until the loop exits, then the answer
		appears. The final post-loop search must pick it up rather than abandon
		the turn.
		"""
		from secator.ai.interactivity import RemoteBackend
		answered_doc = [{"answer": "landed late", "_timestamp": 100.0}]

		def fake_search(query, *args, **kwargs):
			# Answer only becomes visible AFTER the single poll iteration.
			return list(answered_doc) if mock_sleep.call_count >= 1 else []

		mock_engine = MagicMock()
		mock_engine.search.side_effect = fake_search
		mock_engine.update.return_value = 0
		backend = RemoteBackend(timeout=5, query_engine=mock_engine, poll_interval=5)

		result = backend.ask_user("What next?", [], "session1", prompt_uuid="abc-123")

		self.assertIsNotNone(result)
		self.assertEqual(result["answer"], "landed late")

	@patch('secator.ai.interactivity.sleep')
	def test_timeout_noop_flip_rereads_answer(self, mock_sleep):
		"""M10: if the timeout flip modifies 0 rows, re-read the answer."""
		from secator.ai.interactivity import RemoteBackend
		# Empty during the loop AND at the first final search, then the answer
		# appears right as we attempt the (no-op) flip.
		searches = [[], [], [{"answer": "raced in", "_timestamp": 1.0}]]
		mock_engine = MagicMock()
		mock_engine.search.side_effect = lambda *a, **k: searches.pop(0) if searches else []
		mock_engine.update.return_value = 0  # nothing pending -> already answered
		backend = RemoteBackend(timeout=5, query_engine=mock_engine, poll_interval=5)

		result = backend._poll_for_answer("session1", "permission", prompt_uuid="abc-123")
		self.assertEqual(result, "raced in")

	def test_build_pending_prompt_expires_prior_pending(self):
		"""M10: starting a new prompt marks prior still-pending docs stale."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		backend = RemoteBackend(timeout=60, query_engine=mock_engine)

		backend.build_pending_prompt(
			"Target x requires approval", ["allow", "deny"], "session1",
			prompt_type="permission", permission_type="target", value="x",
			prompt_uuid="uuid-new",
		)

		# An update flipping this session's pending docs to timed_out must fire.
		mock_engine.update.assert_called_once()
		flip_query, flip_update = mock_engine.update.call_args[0]
		self.assertEqual(flip_query.get("_context.session_id"), "session1")
		self.assertEqual(flip_query.get("status"), "pending")
		self.assertEqual(flip_update, {"$set": {"status": "timed_out"}})

	def test_expire_stale_pending_noop_without_engine(self):
		"""No query engine -> no crash, no update."""
		from secator.ai.interactivity import RemoteBackend
		backend = RemoteBackend(timeout=60, query_engine=None)
		backend._expire_stale_pending("session1")  # must not raise

	def _permission_backend(self, answer):
		"""RemoteBackend whose poll resolves to `answer` for a shell prompt."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = [{"answer": answer, "_timestamp": 1.0}]
		return RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

	@staticmethod
	def _shell_name_allowed(engine, cmd_name):
		"""True if the engine auto-allows this shell command NAME (no re-prompt).

		Asserted at the command-name layer (``_check_value``) rather than via
		check_action() so the test does not depend on the safecmd/shfmt parser,
		which is not present in every env. This is the exact layer a persisted
		``shell(<cmd>)`` session rule matches on.
		"""
		return engine._check_value("shell", cmd_name).decision == "allow"

	def test_allow_all_persists_session_rule_second_action_auto_allowed(self):
		"""M12: allow_all adds a session-scoped rule; a 2nd matching action needs no prompt."""
		from secator.ai.guardrails import PermissionEngine
		engine = PermissionEngine(config={})  # no static rules: unknown cmd -> no auto-allow
		backend = self._permission_backend("allow_all")

		# Pre-condition: with no rule, the command name is not pre-allowed.
		self.assertFalse(self._shell_name_allowed(engine, "nmap"))

		result = backend.ask_user(
			"Shell `nmap -sV` requires approval", ["deny", "allow", "allow_all"],
			"session1", prompt_type="permission", engine=engine,
			permission_type="shell", value="nmap -sV", prompt_uuid="u1",
		)
		self.assertEqual(result["answer"], "allow")
		# A session-scoped shell(nmap) pattern rule must now be present.
		self.assertTrue(
			any(rt == "shell" and "nmap" in patterns for rt, patterns in engine.runtime_allow),
			"allow_all must persist a session-scoped shell(nmap) rule",
		)
		# A SECOND, DIFFERENT nmap invocation is auto-allowed without a new prompt.
		self.assertTrue(self._shell_name_allowed(engine, "nmap"))

	def test_single_allow_does_not_persist_rule_second_action_reprompts(self):
		"""M12/H9: single allow is one-shot — no rule added, a 2nd match re-prompts."""
		from secator.ai.guardrails import PermissionEngine
		engine = PermissionEngine(config={})
		backend = self._permission_backend("allow")

		result = backend.ask_user(
			"Shell `nmap -sV` requires approval", ["deny", "allow", "allow_all"],
			"session1", prompt_type="permission", engine=engine,
			permission_type="shell", value="nmap -sV", prompt_uuid="u1",
		)
		self.assertEqual(result["answer"], "allow")
		# No session rule was persisted -> a second matching action is not pre-allowed.
		self.assertEqual(engine.runtime_allow, [])
		self.assertFalse(self._shell_name_allowed(engine, "nmap"))

	def test_deny_unchanged_no_rule(self):
		"""deny returns deny and never touches runtime_allow."""
		from secator.ai.guardrails import PermissionEngine
		engine = PermissionEngine(config={})
		backend = self._permission_backend("deny")

		result = backend.ask_user(
			"Shell `nmap` requires approval", ["deny", "allow", "allow_all"],
			"session1", prompt_type="permission", engine=engine,
			permission_type="shell", value="nmap", prompt_uuid="u1",
		)
		self.assertEqual(result["answer"], "deny")
		self.assertEqual(engine.runtime_allow, [])


class TestRemoteBackendSteer(unittest.TestCase):
	"""Verify mid-flight steer draining + the blocked-wait break."""

	def test_poll_steers_returns_and_consumes(self):
		"""poll_steers returns pending steer content and marks them consumed."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = [
			{"content": "actually focus on the API", "_timestamp": 2},
			{"content": "and skip port 80", "_timestamp": 1},
		]
		mock_engine.update = MagicMock()
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		steers = backend.poll_steers("session1")

		# Oldest-first by _timestamp
		self.assertEqual(steers, ["and skip port 80", "actually focus on the API"])
		# Query scoped to pending steer docs for this session
		search_query = mock_engine.search.call_args[0][0]
		self.assertEqual(search_query.get("ai_type"), "steer")
		self.assertEqual(search_query.get("status"), "pending")
		self.assertEqual(search_query.get("_context.session_id"), "session1")
		# Pending steers flipped to consumed (inject exactly once)
		mock_engine.update.assert_called_once()
		update_set = mock_engine.update.call_args[0][1]
		self.assertEqual(update_set["$set"]["status"], "consumed")

	def test_poll_steers_no_pending_returns_empty(self):
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = []
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		self.assertEqual(backend.poll_steers("session1"), [])
		# Nothing to consume when nothing is pending
		mock_engine.update.assert_not_called()

	def test_poll_steers_robust_on_backend_error(self):
		"""A steer must never crash the run: backend errors return []."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.side_effect = RuntimeError("mongo down")
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		self.assertEqual(backend.poll_steers("session1"), [])

	def test_poll_steers_no_query_engine(self):
		from secator.ai.interactivity import RemoteBackend
		backend = RemoteBackend(timeout=60, query_engine=None, poll_interval=0.01)
		self.assertEqual(backend.poll_steers("session1"), [])

	def test_steer_breaks_blocked_follow_up_wait(self):
		"""A steer arriving during a follow-up wait returns as the answer."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		# No follow-up answer ever; a steer arrives on the first poll.
		mock_engine.search.side_effect = [
			[],  # answered? no
			[{"content": "change course now", "_timestamp": 1}],  # poll_steers -> steer
		]
		mock_engine.update = MagicMock()
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		result = backend.ask_user("What next?", [], "session1", prompt_uuid="uuid-1")

		# The steer content resolves the blocked wait (returned as the answer).
		self.assertEqual(result["answer"], "change course now")


class TestCreateBackend(unittest.TestCase):
	"""Verify create_backend factory."""

	def test_local_returns_cli(self):
		from secator.ai.interactivity import create_backend, CLIBackend
		backend = create_backend("local")
		self.assertIsInstance(backend, CLIBackend)

	def test_remote_returns_remote(self):
		from secator.ai.interactivity import create_backend, RemoteBackend
		backend = create_backend("remote", timeout=60, query_engine=MagicMock())
		self.assertIsInstance(backend, RemoteBackend)

	def test_auto_returns_auto(self):
		from secator.ai.interactivity import create_backend, AutoBackend
		backend = create_backend("auto")
		self.assertIsInstance(backend, AutoBackend)

	def test_unknown_returns_auto(self):
		from secator.ai.interactivity import create_backend, AutoBackend
		backend = create_backend("unknown")
		self.assertIsInstance(backend, AutoBackend)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestRemoteTurnPendingDocCoverage(unittest.TestCase):
	"""H5: common remote turns (plain-chat reply, max-iter exit) must not poll on
	prompt_uuid=None. Plain-chat must persist a proper pending doc and poll on its
	real uuid; the max-iter terminal path must not strand a dangling pending doc."""

	class _FakeHistory:
		def add_user(self, *a, **k):
			pass

		def count_tokens_by_role(self, model=None):
			return {"total": 0}

		def to_messages(self, *a, **k):
			return []

	def test_plain_chat_remote_persists_pending_doc_and_polls_on_uuid(self):
		"""A plain-chat remote turn persists a pending follow_up doc with a
		non-None prompt_uuid and polls scoped to THAT uuid (never None)."""
		from secator.tasks.ai import ai as AiTask
		from secator.ai.interactivity import RemoteBackend
		from secator.output_types import Ai

		mock_engine = MagicMock()
		mock_engine.search.return_value = [{"answer": "keep going", "_timestamp": 1.0}]
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)

		persisted = []
		fake_self = MagicMock()
		fake_self.backend = backend
		fake_self.session_id = "sess-chat"
		fake_self.model = "gpt-4o"
		fake_self.mode = "chat"
		fake_self.encryptor = None
		fake_self.max_iterations = 10
		fake_self.history = self._FakeHistory()
		fake_self.add_result = lambda item, **kw: persisted.append(item)

		# plain-chat turn: no prompt_uuid passed in (this is the H5 path)
		items = AiTask._prompt_and_redetect(fake_self, [])

		pend = [p for p in persisted if isinstance(p, Ai) and p.status == "pending"]
		self.assertEqual(len(pend), 1, "exactly one pending doc must be persisted")
		uuid_stamped = (pend[0].extra_data or {}).get("prompt_uuid")
		self.assertTrue(uuid_stamped, "pending doc must carry a real (non-None) prompt_uuid")
		self.assertEqual(pend[0].ai_type, "follow_up")

		# the poll must be scoped to THAT prompt's uuid — never None
		search_query = mock_engine.search.call_args[0][0]
		self.assertEqual(search_query.get("extra_data.prompt_uuid"), uuid_stamped)
		# the answer resolved, so the loop continues (non-None items) rather than exiting
		self.assertIsNotNone(items)

	def test_local_plain_chat_does_not_persist_pending_doc(self):
		"""Local (CLI) plain-chat must NOT create a pending doc — that is a
		remote-channel concern only."""
		from secator.tasks.ai import ai as AiTask
		from secator.ai.interactivity import CLIBackend
		from secator.output_types import Ai

		backend = MagicMock(spec=CLIBackend)
		backend.ask_user.return_value = {"answer": "do x"}

		persisted = []
		fake_self = MagicMock()
		fake_self.backend = backend
		fake_self.session_id = "sess-local"
		fake_self.model = "gpt-4o"
		fake_self.mode = "chat"
		fake_self.encryptor = None
		fake_self.max_iterations = 10
		fake_self.history = self._FakeHistory()
		fake_self.add_result = lambda item, **kw: persisted.append(item)

		AiTask._prompt_and_redetect(fake_self, [])

		pend = [p for p in persisted if isinstance(p, Ai) and p.status == "pending"]
		self.assertEqual(pend, [], "local backend must not persist a pending doc")

	@patch("secator.query.QueryEngine")
	@patch("secator.tasks.ai.init_llm")
	@patch("secator.tasks.ai.call_llm")
	def test_remote_max_iter_does_not_strand_pending_doc(self, mock_call_llm, mock_init, mock_qe_cls):
		"""At remote max-iter after tool work, the loop ends cleanly: it does not
		enter the follow-up poll and does not persist a dangling pending doc."""
		from secator.tasks.ai import ai as AiTask
		from secator.ai.interactivity import RemoteBackend
		from secator.output_types import Ai, Info

		mock_call_llm.return_value = {
			"content": "working", "tool_calls": [object()], "usage": {"tokens": 100, "cost": 0.001},
		}

		persisted = []
		prompt_calls = []
		backend = RemoteBackend(timeout=60, query_engine=MagicMock(), poll_interval=0.01)

		fake_self = MagicMock()
		fake_self.backend = backend
		fake_self.session_id = "sess-max"
		fake_self.model = "gpt-4o"
		fake_self.mode = "chat"
		fake_self.max_iterations = 1
		fake_self.interactive = "remote"
		fake_self.is_subagent = False
		fake_self.inputs = []
		fake_self.context = {}
		fake_self.scope = "workspace"
		fake_self.results = []
		fake_self.max_workers = 3
		fake_self.encryptor = None
		fake_self.dry_run = False
		fake_self.verbose = False
		fake_self._sync = False
		fake_self.temp = 0.7
		fake_self.api_base = ""
		fake_self.api_key = ""
		fake_self.tool_schemas = []
		fake_self.max_tokens_total = 100000
		fake_self.permission_engine = MagicMock()
		fake_self.history = self._FakeHistory()
		fake_self.add_result = lambda item, **kw: persisted.append(item)

		def _empty_gen(*a, **k):
			return
			yield  # pragma: no cover - make it a generator

		fake_self._summarize_auto = _empty_gen
		fake_self._summarize_user = _empty_gen
		fake_self._drain_history_usage = lambda: None
		fake_self._account_usage = lambda u: None
		# _add_assistant_to_history now returns the litellm message dict (the
		# caller feeds it to cap_message(...) for persistence); the stub must
		# match that contract instead of returning None -- a bare None broke
		# cap_message's dict(msg) call and masked this test's real assertions
		# behind a swallowed exception.
		fake_self._add_assistant_to_history = lambda c, t: {"role": "assistant", "content": c}
		fake_self._save_history = lambda: None

		def _fake_process(tool_calls, ctx):
			return [{"action": "shell", "tool_call_id": "t", "tool_call_name": "run_shell"}]
			yield  # pragma: no cover

		fake_self._process_tool_calls = _fake_process

		def _fake_dispatch(actions, ctx):
			return {"follow_up_choices": None, "stop_reason": None, "follow_up_prompt_uuid": None}
			yield  # pragma: no cover

		fake_self._dispatch_and_collect = _fake_dispatch

		def _track_prompt(choices, prompt_uuid=None):
			prompt_calls.append((choices, prompt_uuid))
			return []

		fake_self._prompt_and_redetect = _track_prompt

		items = list(AiTask._run_loop(fake_self))

		self.assertEqual(prompt_calls, [], "remote max-iter must not enter the follow-up poll")
		pend = [p for p in persisted if isinstance(p, Ai) and getattr(p, "status", None) == "pending"]
		self.assertEqual(pend, [], "remote max-iter must not persist a dangling pending doc")
		self.assertTrue(
			any(isinstance(it, Info) and "max iterations" in it.message.lower() for it in items),
			"loop must end via the terminal 'reached max iterations' tail",
		)


if __name__ == "__main__":
	unittest.main()
