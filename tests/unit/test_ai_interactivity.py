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

	def test_ask_user_never_called(self):
		"""AutoBackend.ask_user should raise — it should never be called."""
		from secator.ai.interactivity import AutoBackend
		backend = AutoBackend()
		with self.assertRaises(NotImplementedError):
			backend.ask_user("q", [], "s1")


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

		self.assertEqual(result, "option A")

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

		self.assertEqual(result, "option B")
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
