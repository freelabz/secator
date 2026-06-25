"""Tests for per-run billed AI token accounting.

The `ai` task accumulates billed tokens from every LLM call it makes into
`context.ai_tokens` (and cost into `context.ai_cost`). The platform billing
chore reads `context.ai_tokens` — the AI analog of `context.scan_hours`.

These tests verify:
- N calls with known token counts sum onto `context.ai_tokens`.
- Missing/None usage counts as 0 and never crashes the run.
- History summarization usage is rolled in exactly once.
"""
import contextlib
import unittest
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED

HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.tasks.ai import ai
	from secator.ai.history import ChatHistory


def _make_task():
	"""Construct a bare `ai` task instance with a context dict, bypassing __init__.

	We avoid the full runner construction (which needs a workspace, backend, etc.)
	since the accounting helpers only touch `self.context` and `self.history`.
	"""
	task = ai.__new__(ai)
	task.context = {}
	task.history = ChatHistory()
	# Mirror what _init_options seeds.
	task.context.setdefault("ai_tokens", 0)
	task.context.setdefault("ai_cost", 0.0)
	return task


@unittest.skipUnless(HAS_AI, 'ai addon required')
class TestAiTokenAccounting(unittest.TestCase):

	def test_sum_over_n_calls(self):
		"""N call_llm usages sum onto context.ai_tokens (and ai_cost)."""
		task = _make_task()
		usages = [
			{"tokens": 100, "cost": 0.001},
			{"tokens": 250, "cost": 0.002},
			{"tokens": 50, "cost": 0.0005},
		]
		for u in usages:
			task._account_usage(u)
		self.assertEqual(task.context["ai_tokens"], 400)
		self.assertAlmostEqual(task.context["ai_cost"], 0.0035)

	def test_missing_usage_counts_as_zero(self):
		"""None / empty / missing-key usage never crashes and adds 0."""
		task = _make_task()
		task._account_usage(None)
		task._account_usage({})
		task._account_usage({"tokens": None, "cost": None})
		task._account_usage({"cost": 0.5})  # no tokens key
		self.assertEqual(task.context["ai_tokens"], 0)

	def test_malformed_usage_does_not_crash(self):
		"""Non-numeric token/cost values are ignored, not raised."""
		task = _make_task()
		task._account_usage({"tokens": "abc", "cost": "xyz"})
		task._account_usage({"tokens": 42, "cost": 0.01})
		self.assertEqual(task.context["ai_tokens"], 42)

	def test_field_persisted_on_context(self):
		"""The platform reads context.ai_tokens — confirm that exact key."""
		task = _make_task()
		task._account_usage({"tokens": 123, "cost": 0.0})
		self.assertIn("ai_tokens", task.context)
		self.assertEqual(task.context["ai_tokens"], 123)
		self.assertIsInstance(task.context["ai_tokens"], int)

	def test_history_summarization_usage_drained_once(self):
		"""Billed tokens accrued by history compaction roll in exactly once."""
		task = _make_task()
		# Simulate ChatHistory.compact stashing summarization usage.
		task.history.billed_tokens = 500
		task.history.billed_cost = 0.004
		task._drain_history_usage()
		self.assertEqual(task.context["ai_tokens"], 500)
		self.assertAlmostEqual(task.context["ai_cost"], 0.004)
		# Draining again must not double-count.
		task._drain_history_usage()
		self.assertEqual(task.context["ai_tokens"], 500)

	def test_history_compact_records_billed_usage(self):
		"""ChatHistory.compact accrues the summarization call's billed tokens."""
		history = ChatHistory(model="test-model")
		history.add_system("system")
		history.add_user("u1")
		history.add_assistant("a1")
		history.add_user("u2")
		history.add_assistant("a2")
		history.add_user("u3")
		history.add_assistant("a3")

		fake = {"content": "summary", "usage": {"tokens": 321, "cost": 0.003}}
		with patch('secator.ai.utils.call_llm', return_value=fake):
			with patch('secator.ai.history.get_context_window', return_value=8000):
				history.compact("test-model", keep_last=2)

		self.assertEqual(history.billed_tokens, 321)
		self.assertAlmostEqual(history.billed_cost, 0.003)

	def test_history_compact_missing_usage_is_zero(self):
		"""compact() with no usage on the response adds 0 billed tokens."""
		history = ChatHistory(model="test-model")
		history.add_system("system")
		history.add_user("u1")
		history.add_assistant("a1")
		history.add_user("u2")
		history.add_assistant("a2")
		history.add_user("u3")
		history.add_assistant("a3")

		fake = {"content": "summary", "usage": None}
		with patch('secator.ai.utils.call_llm', return_value=fake):
			with patch('secator.ai.history.get_context_window', return_value=8000):
				history.compact("test-model", keep_last=2)

		self.assertEqual(history.billed_tokens, 0)


@contextlib.contextmanager
def _loop_patches(task, responses):
	"""Patch the heavy collaborators _run_loop touches so we can drive it bare.

	Leaves call_llm token accounting intact (that is what we are testing).
	"""
	with contextlib.ExitStack() as stack:
		stack.enter_context(patch('secator.tasks.ai.call_llm', side_effect=responses))
		stack.enter_context(patch('secator.ai.history.get_context_window', return_value=8000))
		stack.enter_context(patch('secator.tasks.ai.get_context_window', return_value=8000))
		stack.enter_context(patch('secator.tasks.ai.save_history'))
		stack.enter_context(patch.object(type(task), 'reports_folder', property(lambda self: None)))
		stack.enter_context(patch.object(ai, '_summarize_auto', return_value=iter(())))
		stack.enter_context(patch.object(ai, '_summarize_user', return_value=iter(())))
		yield stack


@unittest.skipUnless(HAS_AI, 'ai addon required')
class TestAiTokenAccountingEndToEnd(unittest.TestCase):
	"""Drive the real _run_loop with mocked call_llm and assert the sum lands."""

	def _make_loop_task(self):
		task = _make_task()
		# Minimal state _run_loop reads.
		task.inputs = []
		task.model = "test-model"
		task.intent_model = "test-model"
		task.temp = 0.7
		task.api_base = None
		task.api_key = "key"
		task.max_iterations = 3
		task.max_tokens_total = 100000
		task.max_workers = 1
		task.is_subagent = True
		task.verbose = False
		task.dry_run = False
		task.mode = "chat"
		task.scope = "workspace"
		task.results = []
		task.encryptor = None
		task.tool_schemas = []
		task.permission_engine = None
		task.dangerous = True
		task.interactive = "auto"
		task._sync = True
		task.session_id = "s"
		task._reports_folder = None
		task.debug = lambda *a, **k: None
		task.add_result = lambda *a, **k: None
		from secator.ai.interactivity import create_backend
		task.backend = create_backend("auto")
		return task

	def test_loop_sums_token_usage(self):
		"""Three content responses with known tokens sum onto context.ai_tokens."""
		task = self._make_loop_task()
		responses = [
			{"content": "r1", "tool_calls": [], "usage": {"tokens": 100, "cost": 0.001}},
			{"content": "r2", "tool_calls": [], "usage": {"tokens": 200, "cost": 0.002}},
			{"content": "r3", "tool_calls": [], "usage": {"tokens": 300, "cost": 0.003}},
		]
		# auto backend returns None on follow-up prompt -> loop exits after first
		# content-only response. Force it to keep going by mocking the prompt to
		# add a user turn for the first two, then exit.
		prompt_calls = {"n": 0}

		def fake_prompt(choices):
			prompt_calls["n"] += 1
			if prompt_calls["n"] >= 3:
				return None  # exit
			task.history.add_user("continue")
			return []

		with _loop_patches(task, responses):
			with patch.object(ai, '_prompt_and_redetect', side_effect=fake_prompt):
				list(task._run_loop())

		self.assertEqual(task.context["ai_tokens"], 600)
		self.assertAlmostEqual(task.context["ai_cost"], 0.006)

	def test_loop_with_no_usage_is_zero(self):
		"""Responses without usage leave context.ai_tokens at 0 (no crash)."""
		task = self._make_loop_task()
		responses = [
			{"content": "r1", "tool_calls": [], "usage": None},
		]
		with _loop_patches(task, responses):
			with patch.object(ai, '_prompt_and_redetect', return_value=None):
				list(task._run_loop())

		self.assertEqual(task.context["ai_tokens"], 0)


if __name__ == '__main__':
	unittest.main()
