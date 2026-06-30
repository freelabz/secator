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
		mock_engine.search.side_effect = [
			[],  # first poll: not answered
			[{"answer": "option B"}],  # second poll: answered
		]
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=5)

		result = backend.ask_user("What next?", [], "session1")

		self.assertIsNotNone(result)
		self.assertEqual(result["answer"], "option B")
		self.assertEqual(mock_sleep.call_count, 1)


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
