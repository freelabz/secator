"""Tests for secator.ai.interactivity module."""
import unittest
from unittest.mock import MagicMock, patch


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


if __name__ == "__main__":
	unittest.main()
