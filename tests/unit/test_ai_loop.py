"""Tests for AI loop behavior across interactive modes (local, remote, auto).

Covers three primary scenarios:
- Mode 'local': CLI interactive prompts for permissions and follow-up
- Mode 'remote': DB-polling for permission and follow-up confirmations
- Mode 'auto': Non-interactive, permissions blocked, stop tool exits loop
"""
import json
import unittest
from unittest.mock import MagicMock, patch

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.actions import (
		ActionContext, check_guardrails_sync as check_guardrails, dispatch_action
	)
	from secator.ai.guardrails import PermissionEngine
	from secator.ai.interactivity import CLIBackend, RemoteBackend, AutoBackend, create_backend
	from secator.ai.tools import build_tool_schemas, tool_call_to_action
	from secator.ai.prompts import get_system_prompt
	from secator.ai.history import ChatHistory
	from secator.output_types import Ai


def _make_tool_call(name, args, tc_id=None):
	"""Create a mock litellm tool call object."""
	tc = MagicMock()
	tc.id = tc_id or f"call_{name}"
	tc.function.name = name
	tc.function.arguments = json.dumps(args) if isinstance(args, dict) else args
	return tc


def _make_llm_response(content=None, tool_calls=None, tokens=100):
	"""Create a call_llm return dict."""
	return {
		"content": content,
		"tool_calls": tool_calls or [],
		"usage": {"tokens": tokens, "cost": 0.001}
	}


def _make_permission_config():
	"""Create a minimal permission config for testing."""
	return {
		"allow": [
			"target(10.0.0.1)",
			"read(/tmp/*)",
			"write(/tmp/*)",
			"shell(curl,wget,cat,ls,grep,echo,nmap)",
			"task(*)",
			"workflow(*)",
		],
		"deny": [],
		"ask": [],
	}


def _make_ctx(interactive="local", backend=None, session_id="test-session", targets=None, engine=None):
	"""Create an ActionContext with given interactive mode.

	Always creates a backend (check_guardrails requires it for prompting).
	Pass backend=<mock> to override the default.
	"""
	if engine is None:
		engine = PermissionEngine(_make_permission_config(), targets=targets or ["10.0.0.1"], workspace="/tmp/ws")
	if backend is None:
		backend = create_backend(interactive)
	return ActionContext(
		targets=targets or ["10.0.0.1"],
		model="test-model",
		interactive=interactive,
		backend=backend,
		session_id=session_id,
		permission_engine=engine,
	)


# =============================================================================
# UNIT TESTS: Guardrails behavior per interactive mode
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestGuardrailsLocalMode(unittest.TestCase):
	"""Test guardrails prompt flow in local (CLI) interactive mode."""

	def test_allowed_command_passes_without_prompt(self):
		"""Commands in the allow list pass without any prompting."""
		ctx = _make_ctx(interactive="local")
		action = {"action": "shell", "command": "curl http://10.0.0.1/api"}
		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNone(denial)

	def test_unknown_command_prompts_user_and_approves(self):
		"""Unknown commands trigger prompt_shell; approval continues the loop."""
		ctx = _make_ctx(interactive="local")
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		def mock_approve(command, reason="", interactive=True):
			# Simulate what the real prompt_shell does: add runtime rule on approval
			ctx.permission_engine.add_runtime_allow(["shell(python3)"])
			return "allow"

		with patch.object(ctx.permission_engine, 'prompt_shell', side_effect=mock_approve) as mock_prompt:
			denial, warnings = check_guardrails(action, ctx)

		self.assertIsNone(denial, f"Expected approval but got: {denial}")
		mock_prompt.assert_called_once()

	def test_unknown_command_prompts_user_and_denies(self):
		"""User denying the shell prompt blocks the action."""
		ctx = _make_ctx(interactive="local")
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		def mock_deny(command, reason="", interactive=True):
			ctx.permission_engine.add_runtime_allow([])  # no-op, just for consistency
			return "deny"

		with patch.object(ctx.permission_engine, 'prompt_shell', side_effect=mock_deny):
			denial, warnings = check_guardrails(action, ctx)

		self.assertIsNotNone(denial)
		self.assertIn("not approved", denial)

	def test_unknown_target_prompts_and_approves(self):
		"""Targets not in the allow list trigger prompt_target."""
		ctx = _make_ctx(interactive="local")
		action = {"action": "shell", "command": "curl http://unknown-host.com/api"}

		def mock_shell_approve(command, reason="", interactive=True):
			ctx.permission_engine.add_runtime_allow(["shell(curl)"])
			return "allow"

		def mock_target_approve(target, interactive=True, command=""):
			ctx.permission_engine.add_runtime_allow([f"target({target})"])
			return "allow"

		with patch.object(ctx.permission_engine, 'prompt_shell', side_effect=mock_shell_approve):
			with patch.object(ctx.permission_engine, 'prompt_target', side_effect=mock_target_approve):
				denial, warnings = check_guardrails(action, ctx)

		self.assertIsNone(denial, f"Expected approval but got: {denial}")


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestGuardrailsRemoteMode(unittest.TestCase):
	"""Test guardrails prompt flow in remote (DB-polling) mode."""

	def test_allowed_command_passes_without_prompt(self):
		"""Commands in the allow list pass without remote prompting."""
		mock_backend = MagicMock(spec=RemoteBackend)
		ctx = _make_ctx(interactive="remote", backend=mock_backend)
		action = {"action": "shell", "command": "curl http://10.0.0.1/api"}

		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNone(denial)
		mock_backend.ask_user.assert_not_called()

	def test_unknown_command_remote_confirm_approves(self):
		"""Unknown commands are confirmed via remote backend (DB polling)."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		def mock_ask(question="", choices=None, session_id="", prompt_type="", **kwargs):
			# Simulate RemoteBackend: add rules on approval
			if prompt_type == "permission":
				eng = kwargs.get("engine")
				ptype = kwargs.get("permission_type")
				value = kwargs.get("value", "")
				if eng:
					RemoteBackend._add_permission_rules(eng, ptype, value)
				return {"answer": "allow"}
			return {"answer": "yes"}

		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.side_effect = mock_ask
		ctx = _make_ctx(interactive="remote", backend=mock_backend, engine=engine)
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		denial, warnings = check_guardrails(action, ctx)

		self.assertIsNone(denial, f"Expected approval but got: {denial}")
		mock_backend.ask_user.assert_called()

	def test_unknown_command_remote_confirm_denies(self):
		"""Remote denial blocks the action."""
		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.return_value = {"answer": "deny"}
		ctx = _make_ctx(interactive="remote", backend=mock_backend)
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		denial, warnings = check_guardrails(action, ctx)

		self.assertIsNotNone(denial)
		self.assertIn("not approved", denial)

	def test_remote_confirm_adds_runtime_rule(self):
		"""After remote approval, the command is added as a runtime allow rule."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		def mock_ask(question="", choices=None, session_id="", prompt_type="", **kwargs):
			if prompt_type == "permission":
				eng = kwargs.get("engine")
				ptype = kwargs.get("permission_type")
				value = kwargs.get("value", "")
				if eng:
					RemoteBackend._add_permission_rules(eng, ptype, value)
				return {"answer": "allow"}
			return {"answer": "yes"}

		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.side_effect = mock_ask
		ctx = _make_ctx(interactive="remote", backend=mock_backend, engine=engine)
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		check_guardrails(action, ctx)

		# Second call should not need remote prompting (runtime rule added)
		mock_backend.ask_user.reset_mock()
		denial2, _ = check_guardrails(action, ctx)
		self.assertIsNone(denial2)
		# The backend should NOT be called for shell again
		shell_calls = [c for c in mock_backend.ask_user.call_args_list
					   if "python3" in str(c)]
		self.assertEqual(len(shell_calls), 0, "Shell command should be allowed by runtime rule on second call")

	def test_remote_timeout_denies(self):
		"""When remote backend times out (returns None), action is denied."""
		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.return_value = None  # Timeout
		ctx = _make_ctx(interactive="remote", backend=mock_backend)
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNotNone(denial)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestGuardrailsAutoMode(unittest.TestCase):
	"""Test guardrails in auto (non-interactive) mode."""

	def test_allowed_command_passes(self):
		"""Commands in the allow list pass in auto mode."""
		ctx = _make_ctx(interactive="auto")
		action = {"action": "shell", "command": "curl http://10.0.0.1/api"}
		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNone(denial)

	def test_unknown_command_blocked(self):
		"""Unknown commands are auto-denied in auto mode (no interactivity)."""
		ctx = _make_ctx(interactive="auto")
		action = {"action": "shell", "command": "python3 exploit.py 10.0.0.1"}

		denial, warnings = check_guardrails(action, ctx)

		self.assertIsNotNone(denial)
		self.assertIn("not approved", denial)

	def test_unknown_target_blocked(self):
		"""Unknown targets are auto-denied in auto mode."""
		ctx = _make_ctx(interactive="auto")
		action = {"action": "shell", "command": "curl http://unknown.com"}

		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNotNone(denial)


# =============================================================================
# UNIT TESTS: Follow-up and stop handling per mode
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestFollowUpDispatch(unittest.TestCase):
	"""Test follow_up action dispatch across modes."""

	def test_follow_up_yields_ai_with_choices(self):
		"""follow_up action yields Ai object with choices."""
		ctx = _make_ctx(interactive="local")
		action = {
			"action": "follow_up",
			"reason": "Scan complete. What next?",
			"choices": ["Exploit XSS", "Continue scanning", "Generate report"],
			"tool_call_id": "tc_fu",
			"tool_call_name": "follow_up",
		}
		results = list(dispatch_action(action, ctx))
		ai_results = [r for r in results if isinstance(r, Ai)]
		self.assertTrue(len(ai_results) >= 1)
		fu = ai_results[0]
		self.assertEqual(fu.ai_type, "follow_up")
		self.assertIn("Exploit XSS", (fu.extra_data or {}).get("choices", []))

	def test_stop_yields_ai_stopped(self):
		"""stop action yields Ai object with ai_type='stopped'."""
		ctx = _make_ctx(interactive="auto")
		action = {
			"action": "stop",
			"reason": "Task completed successfully",
			"tool_call_id": "tc_stop",
			"tool_call_name": "stop",
		}
		results = list(dispatch_action(action, ctx))
		ai_results = [r for r in results if isinstance(r, Ai)]
		self.assertTrue(len(ai_results) >= 1)
		self.assertEqual(ai_results[0].ai_type, "stopped")
		self.assertIn("completed", ai_results[0].content)


# =============================================================================
# UNIT TESTS: Remote follow-up persistence (status + top-level choices)
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestRemoteFollowUpPersistence(unittest.TestCase):
	"""In remote mode, the single persisted follow-up doc must be renderable:
	status=="pending" + non-empty top-level `choices` (what the web UI reads)."""

	def _run_dispatch(self, backend):
		"""Drive the real ai._dispatch_and_collect with a minimal fake self.

		Returns (yielded_items, persisted_items) where persisted_items are what
		add_result() received (i.e. what the mongodb on_item hook would persist).
		"""
		from secator.tasks.ai import ai as AiTask

		choices = ["Fuzz parameters", "Run nuclei", "Deep crawl"]
		follow_up = Ai(
			content="Presenting actionable next steps",
			ai_type="follow_up",
			extra_data={"choices": choices},
			_context={"tool_call_id": "tc_fu", "tool_call_name": "follow_up"},
		)

		persisted = []

		class _FakeHistory:
			def get_action_budget(self, model):
				return 10000

			def add_tool_result(self, *a, **k):
				pass

		fake_self = MagicMock()
		fake_self.backend = backend
		fake_self.session_id = "sess-123"
		fake_self.model = "test-model"
		fake_self.reports_folder = None
		fake_self.history = _FakeHistory()
		fake_self.add_result = lambda item, **kw: persisted.append(item)

		ctx = MagicMock()
		ctx.results = []

		def _fake_dispatch_action(action, c):
			yield follow_up

		with patch("secator.tasks.ai.safe_dispatch_action", _fake_dispatch_action):
			gen = AiTask._dispatch_and_collect(fake_self, [{"tool_call_id": "tc_fu"}], ctx)
			yielded = list(gen)
		return yielded, persisted, follow_up

	def test_remote_follow_up_persisted_pending_with_choices(self):
		backend = RemoteBackend(timeout=60, query_engine=MagicMock())
		yielded, persisted, follow_up = self._run_dispatch(backend)

		# Exactly one follow_up Ai is persisted (no duplicate display + pending docs).
		fu_docs = [p for p in persisted if isinstance(p, Ai) and p.ai_type == "follow_up"]
		self.assertEqual(len(fu_docs), 1)
		doc = fu_docs[0]
		self.assertEqual(doc.status, "pending")
		self.assertEqual(doc.choices, ["Fuzz parameters", "Run nuclei", "Deep crawl"])
		self.assertEqual(doc.session_id, "sess-123")
		# Same object → single doc by _uuid.
		self.assertIs(doc, follow_up)

	def test_local_follow_up_not_stamped_pending(self):
		"""CLI/local mode must NOT stamp status=pending (drives the TUI menu directly)."""
		backend = CLIBackend()
		yielded, persisted, follow_up = self._run_dispatch(backend)
		fu_docs = [p for p in persisted if isinstance(p, Ai) and p.ai_type == "follow_up"]
		self.assertEqual(len(fu_docs), 1)
		self.assertNotEqual(fu_docs[0].status, "pending")


# =============================================================================
# UNIT TESTS: Backend and tool schema behavior
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestBackendToolSchemas(unittest.TestCase):
	"""Test that backends control tool availability correctly."""

	def test_local_backend_excludes_stop(self):
		"""CLIBackend excludes the stop tool."""
		backend = CLIBackend()
		schemas = build_tool_schemas("attack", backend=backend)
		names = {s["function"]["name"] for s in schemas}
		self.assertNotIn("stop", names)
		self.assertIn("follow_up", names)

	def test_auto_backend_excludes_follow_up_includes_stop(self):
		"""AutoBackend excludes follow_up and injects stop."""
		backend = AutoBackend()
		schemas = build_tool_schemas("attack", backend=backend)
		names = {s["function"]["name"] for s in schemas}
		self.assertNotIn("follow_up", names)
		self.assertIn("stop", names)

	def test_remote_backend_excludes_stop(self):
		"""RemoteBackend excludes stop (uses follow_up via DB polling)."""
		backend = RemoteBackend(timeout=60, query_engine=MagicMock())
		schemas = build_tool_schemas("attack", backend=backend)
		names = {s["function"]["name"] for s in schemas}
		self.assertNotIn("stop", names)
		self.assertIn("follow_up", names)

	def test_system_prompt_includes_stop_rules_for_auto(self):
		"""Auto backend's system prompt includes stop rules."""
		backend = AutoBackend()
		prompt = get_system_prompt("attack", workspace_path="/tmp/ws", backend=backend)
		self.assertIn("<stop>", prompt)
		self.assertNotIn("<follow_up>", prompt.split("<stop>")[-1])  # stop rules at end

	def test_system_prompt_no_stop_for_local(self):
		"""Local backend's system prompt does not append stop rules."""
		backend = CLIBackend()
		prompt = get_system_prompt("attack", workspace_path="/tmp/ws", backend=backend)
		self.assertNotIn("<stop>", prompt)


# =============================================================================
# INTEGRATION: Remote permission prompt helper
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestRemoteBackendPermissions(unittest.TestCase):
	"""Test RemoteBackend._add_permission_rules (rule addition logic)."""

	def test_shell_rule_added(self):
		"""Shell permission adds a shell runtime rule."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
		RemoteBackend._add_permission_rules(engine, "shell", "python3 exploit.py")

		check = engine._check_value("shell", "python3")
		self.assertEqual(check.decision, "allow")

	def test_target_rule_added(self):
		"""Target permission adds a target runtime rule."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
		RemoteBackend._add_permission_rules(engine, "target", "evil.com")

		check = engine._check_value("target", "evil.com")
		self.assertEqual(check.decision, "allow")

	def test_path_rule_added(self):
		"""Read/write permission adds a path runtime rule."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
		RemoteBackend._add_permission_rules(engine, "read", "/etc/passwd")

		check = engine._check_value("read", "/etc/passwd")
		self.assertEqual(check.decision, "allow")

	def test_full_remote_permission_flow(self):
		"""Full flow: RemoteBackend polls, gets 'allow', adds rules."""
		mock_engine = MagicMock()
		mock_engine.search.return_value = [{"answer": "allow"}]
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)
		result = backend.ask_user(
			"Allow shell: python3?", ["allow", "deny"], "sess1",
			prompt_type="permission", permission_type="shell",
			value="python3 exploit.py", engine=engine
		)

		self.assertIsNotNone(result)
		self.assertEqual(result["answer"], "allow")
		check = engine._check_value("shell", "python3")
		self.assertEqual(check.decision, "allow")


# =============================================================================
# INTEGRATION: Full flow tests per mode
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestLocalModeFlow(unittest.TestCase):
	"""Integration test: Mode 'local' full flow.

	User prompt → AI actions → run_shell() → ask for cmd → manual confirm
	→ loop continues → follow_up → manual selection → continues with updated prompt
	"""

	def test_full_local_flow(self):
		"""E2E local mode: shell(ask→confirm) → dispatch → follow_up → select → continue."""
		ctx = _make_ctx(interactive="local")
		history = ChatHistory()

		# === Turn 1: Shell command that requires permission ===
		shell_action = {
			"action": "shell",
			"command": "python3 exploit.py 10.0.0.1",
			"tool_call_id": "tc1",
			"tool_call_name": "run_shell",
		}

		# Guardrails: python3 not allowed → prompts user → user approves
		def mock_approve(command, reason="", interactive=True):
			ctx.permission_engine.add_runtime_allow(["shell(python3)"])
			return "allow"

		with patch.object(ctx.permission_engine, 'prompt_shell', side_effect=mock_approve) as mock_shell_prompt:
			denial, warnings = check_guardrails(shell_action, ctx)

		self.assertIsNone(denial, f"Expected approval but got: {denial}")
		mock_shell_prompt.assert_called_once()

		# Dispatch the approved action
		with patch('secator.ai.actions.subprocess.run') as mock_run:
			mock_run.return_value = MagicMock(stdout="exploit output\n", stderr="")
			results1 = list(dispatch_action(shell_action, ctx))

		# Verify shell output was produced
		ai_results = [r for r in results1 if isinstance(r, Ai)]
		self.assertTrue(any(r.ai_type == "shell_output" for r in ai_results),
						f"Expected shell_output, got: {[r.ai_type for r in ai_results]}")

		# Add to history (simulating the main loop)
		history.add_assistant_with_tool_calls(None, [_make_tool_call("run_shell", shell_action)])
		history.add_tool_result("run_shell", "tc1", json.dumps({"status": "success", "results": ["exploit output"]}))

		# === Turn 2: Follow-up with choices ===
		follow_up_action = {
			"action": "follow_up",
			"reason": "Exploit succeeded. What next?",
			"choices": ["Pivot to internal network", "Generate report"],
			"tool_call_id": "tc2",
			"tool_call_name": "follow_up",
		}

		results2 = list(dispatch_action(follow_up_action, ctx))
		fu_results = [r for r in results2 if isinstance(r, Ai) and r.ai_type == "follow_up"]
		self.assertEqual(len(fu_results), 1)
		fu = fu_results[0]
		self.assertEqual(fu.content, "Exploit succeeded. What next?")

		# Simulate user selecting "Pivot to internal network" via prompt_user
		selected_choice = "Pivot to internal network"
		history.add_user(selected_choice)

		# Verify history has the full flow
		messages = history.to_messages()
		self.assertTrue(len(messages) >= 3)
		# Last user message should be the selected choice
		user_msgs = [m for m in messages if m["role"] == "user"]
		self.assertEqual(user_msgs[-1]["content"], selected_choice)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestRemoteModeFlow(unittest.TestCase):
	"""Integration test: Mode 'remote' full flow.

	User prompt → AI actions → run_shell() → ask for cmd → remote confirm
	(adding prompt response to workspace → query ws → finds confirmation)
	→ loop continues normally
	"""

	def test_full_remote_flow(self):
		"""E2E remote mode: shell(ask→remote confirm) → dispatch → follow_up → remote answer."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		def mock_ask(question="", choices=None, session_id="", prompt_type="", **kwargs):
			if prompt_type == "permission":
				eng = kwargs.get("engine")
				ptype = kwargs.get("permission_type")
				value = kwargs.get("value", "")
				if eng:
					RemoteBackend._add_permission_rules(eng, ptype, value)
				return {"answer": "allow"}
			return {"answer": "Pivot to internal network"}

		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.side_effect = mock_ask
		ctx = _make_ctx(interactive="remote", backend=mock_backend, engine=engine, session_id="remote-sess-1")
		history = ChatHistory()

		# === Turn 1: Shell command that requires permission ===
		shell_action = {
			"action": "shell",
			"command": "python3 exploit.py 10.0.0.1",
			"tool_call_id": "tc1",
			"tool_call_name": "run_shell",
		}

		# Guardrails: python3 not allowed → asks remote backend → approved
		denial, warnings = check_guardrails(shell_action, ctx)
		self.assertIsNone(denial, f"Expected approval but got: {denial}")

		# Dispatch the approved action
		with patch('secator.ai.actions.subprocess.run') as mock_run:
			mock_run.return_value = MagicMock(stdout="exploit output\n", stderr="")
			results1 = list(dispatch_action(shell_action, ctx))

		ai_results = [r for r in results1 if isinstance(r, Ai)]
		self.assertTrue(any(r.ai_type == "shell_output" for r in ai_results))

		# === Turn 2: Follow-up answered via remote backend ===
		follow_up_action = {
			"action": "follow_up",
			"reason": "Exploit succeeded. What next?",
			"choices": ["Pivot to internal network", "Generate report"],
			"tool_call_id": "tc2",
			"tool_call_name": "follow_up",
		}

		results2 = list(dispatch_action(follow_up_action, ctx))
		fu = next(r for r in results2 if isinstance(r, Ai) and r.ai_type == "follow_up")

		# Simulate the main loop's follow-up handling via backend.ask_user
		fu.status = "pending"
		fu.session_id = ctx.session_id
		response = mock_backend.ask_user(
			question=fu.content,
			choices=fu.choices or fu.extra_data.get("choices", []),
			session_id=ctx.session_id,
			prompt_type="follow_up",
		)
		self.assertEqual(response["answer"], "Pivot to internal network")

		# Add to history and continue
		history.add_user(response["answer"])
		user_msgs = [m for m in history.to_messages() if m["role"] == "user"]
		self.assertEqual(user_msgs[-1]["content"], "Pivot to internal network")

	def test_remote_permission_workspace_roundtrip(self):
		"""Verify remote permission uses workspace query engine for confirmation.

		Simulates: write permission_request → client answers → query finds answer.
		"""
		mock_qe = MagicMock()
		# Simulate: first search returns nothing (pending), second returns answered
		mock_qe.search.side_effect = [
			[],  # First poll: no answer yet
			[{"answer": "allow"}],  # Second poll: answer found
		]
		perm_engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		backend = RemoteBackend(timeout=60, query_engine=mock_qe, poll_interval=0.01)

		with patch('secator.ai.interactivity.sleep'):
			result = backend.ask_user(
				"Allow python3?", ["allow", "deny"], "sess1",
				prompt_type="permission", permission_type="shell",
				value="python3 exploit.py", engine=perm_engine,
			)

		self.assertIsNotNone(result)
		self.assertEqual(result["answer"], "allow")
		self.assertEqual(mock_qe.search.call_count, 2)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestAutoModeFlow(unittest.TestCase):
	"""Integration test: Mode 'auto' (non-interactive) flow.

	User prompt → AI actions → run_shell() → ask for cmd → blocked
	→ loop continues with denial message
	"""

	def test_full_auto_flow_unknown_cmd_blocked(self):
		"""E2E auto mode: unknown shell command blocked, loop continues."""
		ctx = _make_ctx(interactive="auto")
		history = ChatHistory()

		# Shell command not in allow list
		shell_action = {
			"action": "shell",
			"command": "python3 exploit.py 10.0.0.1",
			"tool_call_id": "tc1",
			"tool_call_name": "run_shell",
		}

		# Guardrails: blocked (no interactivity)
		denial, warnings = check_guardrails(shell_action, ctx)
		self.assertIsNotNone(denial)
		self.assertIn("not approved", denial)

		# In the main loop, the denial is added to history as a tool result error
		error_msg = json.dumps({"error": denial})
		history.add_tool_result("run_shell", "tc1", error_msg)

		# Loop continues: LLM gets the error and can try a different approach
		messages = history.to_messages()
		tool_msgs = [m for m in messages if m.get("role") == "tool"]
		self.assertEqual(len(tool_msgs), 1)
		self.assertIn("not approved", tool_msgs[0]["content"])

	def test_allowed_command_runs_in_auto_mode(self):
		"""Commands in the allow list execute normally in auto mode."""
		ctx = _make_ctx(interactive="auto")
		action = {"action": "shell", "command": "curl http://10.0.0.1/api",
				  "tool_call_id": "tc1", "tool_call_name": "run_shell"}

		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNone(denial)

		with patch('secator.ai.actions.subprocess.run') as mock_run:
			mock_run.return_value = MagicMock(stdout="response data", stderr="")
			results = list(dispatch_action(action, ctx))

		ai_results = [r for r in results if isinstance(r, Ai)]
		self.assertTrue(any(r.ai_type == "shell_output" for r in ai_results))

	def test_stop_action_signals_exit(self):
		"""In auto mode, stop action yields 'stopped' Ai for loop exit."""
		ctx = _make_ctx(interactive="auto")
		action = {
			"action": "stop",
			"reason": "All tasks completed",
			"tool_call_id": "tc_stop",
			"tool_call_name": "stop",
		}
		results = list(dispatch_action(action, ctx))
		stopped = [r for r in results if isinstance(r, Ai) and r.ai_type == "stopped"]
		self.assertEqual(len(stopped), 1)
		self.assertIn("completed", stopped[0].content)


# =============================================================================
# INTEGRATION: Subagent permission delegation (auto + sync=True)
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestSubagentPermissionDelegation(unittest.TestCase):
	"""Test subagent → parent permission delegation flow.

	Mode 'auto' (sync=True): Subagent hits permission block → yields
	PermissionRequest to parent → parent confirms → subagent retries.

	NOTE: This tests the building blocks for the delegation pattern.
	Full end-to-end requires the main loop changes (future work).
	"""

	def test_subagent_inherits_parent_runtime_rules(self):
		"""When parent approves a command, subagent with same engine can use it."""
		# Parent approves python3 via local prompt
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
		parent_ctx = _make_ctx(interactive="local", engine=engine)

		def mock_approve(command, reason="", interactive=True):
			engine.add_runtime_allow(["shell(python3)"])
			return "allow"

		with patch.object(engine, 'prompt_shell', side_effect=mock_approve):
			denial, _ = check_guardrails(
				{"action": "shell", "command": "python3 exploit.py 10.0.0.1"}, parent_ctx)
		self.assertIsNone(denial)

		# Subagent uses the SAME engine (shared reference)
		subagent_ctx = _make_ctx(interactive="auto", engine=engine)
		denial2, _ = check_guardrails(
			{"action": "shell", "command": "python3 another.py 10.0.0.1"}, subagent_ctx)
		self.assertIsNone(denial2, "Subagent should inherit parent's runtime allow for python3")

	def test_subagent_blocked_without_parent_approval(self):
		"""Subagent in auto mode is blocked for unapproved commands."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
		subagent_ctx = _make_ctx(interactive="auto", engine=engine)

		denial, _ = check_guardrails(
			{"action": "shell", "command": "python3 exploit.py 10.0.0.1"}, subagent_ctx)
		self.assertIsNotNone(denial)

	def test_parent_remote_approval_visible_to_subagent(self):
		"""Parent approves via remote backend; subagent (shared engine) can use it."""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		def mock_ask(question="", choices=None, session_id="", prompt_type="", **kwargs):
			if prompt_type == "permission":
				eng = kwargs.get("engine")
				ptype = kwargs.get("permission_type")
				value = kwargs.get("value", "")
				if eng:
					RemoteBackend._add_permission_rules(eng, ptype, value)
				return {"answer": "allow"}
			return {"answer": "yes"}

		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.side_effect = mock_ask

		# Parent running in remote mode approves
		parent_ctx = _make_ctx(interactive="remote", backend=mock_backend, engine=engine)
		denial, _ = check_guardrails(
			{"action": "shell", "command": "python3 exploit.py 10.0.0.1"}, parent_ctx)
		self.assertIsNone(denial)

		# Subagent with shared engine can now use it
		subagent_ctx = _make_ctx(interactive="auto", engine=engine)
		denial2, _ = check_guardrails(
			{"action": "shell", "command": "python3 another.py 10.0.0.1"}, subagent_ctx)
		self.assertIsNone(denial2)


# =============================================================================
# E2E: Main loop simulation (multi-turn)
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestMainLoopLocalE2E(unittest.TestCase):
	"""Simulate the main loop for local mode: multi-turn with guardrails and follow-up."""

	def test_multi_turn_local_loop(self):
		"""Full multi-turn simulation:
		Turn 1: LLM → run_shell (needs permission) → approved → executes
		Turn 2: LLM → follow_up → user selects choice → loop continues
		Turn 3: LLM → text response (no tools) → loop ends
		"""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
		ctx = _make_ctx(interactive="local", engine=engine)
		history = ChatHistory()
		history.add_system("You are a pentester.")
		history.add_user("Scan 10.0.0.1")

		# --- Turn 1: LLM returns shell tool call ---
		llm_response_1 = _make_llm_response(
			content="I'll scan the target.",
			tool_calls=[_make_tool_call("run_shell", {"command": "nmap -sV 10.0.0.1"}, "tc1")]
		)

		# Process tool calls (simulating main loop logic)
		tc = llm_response_1["tool_calls"][0]
		action = tool_call_to_action(tc.function.name, json.loads(tc.function.arguments))
		action["tool_call_id"] = tc.id
		action["tool_call_name"] = tc.function.name

		# nmap IS in the allowed list, so no prompt needed
		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNone(denial)

		# Dispatch
		with patch('secator.ai.actions.subprocess.run') as mock_subprocess:
			mock_subprocess.return_value = MagicMock(stdout="scan results\n", stderr="")
			results1 = list(dispatch_action(action, ctx))
		self.assertTrue(any(isinstance(r, Ai) and r.ai_type == "shell_output" for r in results1))

		# Add to history
		history.add_assistant_with_tool_calls("I'll scan the target.", llm_response_1["tool_calls"])
		history.add_tool_result("run_shell", "tc1", '{"status":"success","results":["scan results"]}')

		# --- Turn 2: LLM returns follow_up ---
		llm_response_2 = _make_llm_response(
			content=None,
			tool_calls=[_make_tool_call("follow_up", {
				"reason": "Found open ports. What next?",
				"choices": ["Exploit SSH", "Scan more ports"]
			}, "tc2")]
		)

		tc2 = llm_response_2["tool_calls"][0]
		action2 = tool_call_to_action(tc2.function.name, json.loads(tc2.function.arguments))
		action2["tool_call_id"] = tc2.id
		action2["tool_call_name"] = tc2.function.name

		results2 = list(dispatch_action(action2, ctx))
		fu = next(r for r in results2 if isinstance(r, Ai) and r.ai_type == "follow_up")
		follow_up_choices = (fu.extra_data or {}).get("choices", [])
		self.assertEqual(follow_up_choices, ["Exploit SSH", "Scan more ports"])

		# User selects "Exploit SSH"
		history.add_assistant_with_tool_calls(None, llm_response_2["tool_calls"])
		history.add_tool_result("follow_up", "tc2", '{"status":"success"}')
		history.add_user("Exploit SSH")

		# Verify the conversation flow
		messages = history.to_messages()
		roles = [m["role"] for m in messages]
		self.assertEqual(roles, ["system", "user", "assistant", "tool", "assistant", "tool", "user"])
		self.assertEqual(messages[-1]["content"], "Exploit SSH")


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestMainLoopRemoteE2E(unittest.TestCase):
	"""Simulate the main loop for remote mode: multi-turn with remote confirms."""

	def test_multi_turn_remote_loop(self):
		"""Full multi-turn simulation:
		Turn 1: LLM → run_shell (needs permission) → remote approved → executes
		Turn 2: LLM → follow_up → remote answer → loop continues
		"""
		engine = PermissionEngine(_make_permission_config(), targets=["10.0.0.1"], workspace="/tmp/ws")

		call_count = [0]
		def mock_ask(question="", choices=None, session_id="", prompt_type="", **kwargs):
			call_count[0] += 1
			if prompt_type == "permission":
				eng = kwargs.get("engine")
				ptype = kwargs.get("permission_type")
				value = kwargs.get("value", "")
				if eng:
					RemoteBackend._add_permission_rules(eng, ptype, value)
				return {"answer": "allow"}
			# follow_up
			return {"answer": "Exploit SSH"}

		mock_backend = MagicMock(spec=RemoteBackend)
		mock_backend.ask_user.side_effect = mock_ask

		ctx = _make_ctx(interactive="remote", backend=mock_backend, engine=engine, session_id="remote-e2e")
		history = ChatHistory()
		history.add_system("You are a pentester.")
		history.add_user("Scan 10.0.0.1")

		# --- Turn 1: Shell command needing remote permission ---
		action = {
			"action": "shell",
			"command": "python3 scanner.py 10.0.0.1",
			"tool_call_id": "tc1",
			"tool_call_name": "run_shell",
		}

		denial, warnings = check_guardrails(action, ctx)
		self.assertIsNone(denial, f"Expected remote approval but got: {denial}")

		# Dispatch (mock subprocess only around dispatch_action)
		with patch('secator.ai.actions.subprocess.run') as mock_subprocess:
			mock_subprocess.return_value = MagicMock(stdout="scan results\n", stderr="")
			results1 = list(dispatch_action(action, ctx))
		self.assertTrue(any(isinstance(r, Ai) and r.ai_type == "shell_output" for r in results1))

		# --- Turn 2: Follow-up via remote backend ---
		action2 = {
			"action": "follow_up",
			"reason": "Found vulns. What next?",
			"choices": ["Exploit SSH", "Report"],
			"tool_call_id": "tc2",
			"tool_call_name": "follow_up",
		}
		results2 = list(dispatch_action(action2, ctx))
		fu = next(r for r in results2 if isinstance(r, Ai) and r.ai_type == "follow_up")

		# Remote follow-up polling (simulating main loop via _prompt_and_redetect)
		fu.status = "pending"
		fu.session_id = ctx.session_id
		response = mock_backend.ask_user(
			question=fu.content,
			choices=fu.extra_data.get("choices", []),
			session_id=ctx.session_id,
			prompt_type="follow_up",
		)
		self.assertEqual(response["answer"], "Exploit SSH")
		history.add_user(response["answer"])

		# Verify call sequence: permission calls + 1 follow-up
		self.assertGreaterEqual(call_count[0], 2)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestMainLoopAutoE2E(unittest.TestCase):
	"""Simulate the main loop for auto mode: non-interactive."""

	def test_multi_turn_auto_loop(self):
		"""Full multi-turn simulation:
		Turn 1: LLM → run_shell (unknown cmd) → blocked → error in history
		Turn 2: LLM → run_shell (allowed cmd) → executes
		Turn 3: LLM → stop → loop exits
		"""
		ctx = _make_ctx(interactive="auto")
		history = ChatHistory()
		history.add_system("You are a pentester.")
		history.add_user("Scan 10.0.0.1")

		# --- Turn 1: Unknown command → blocked ---
		action1 = {
			"action": "shell",
			"command": "python3 exploit.py 10.0.0.1",
			"tool_call_id": "tc1",
			"tool_call_name": "run_shell",
		}
		denial, _ = check_guardrails(action1, ctx)
		self.assertIsNotNone(denial, "Unknown command should be blocked in auto mode")

		# Add denial to history (simulating main loop)
		error_msg = json.dumps({"error": denial, "hint": "Try an allowed command."})
		history.add_tool_result("run_shell", "tc1", error_msg)

		# --- Turn 2: Allowed command → executes ---
		action2 = {
			"action": "shell",
			"command": "curl http://10.0.0.1/api",
			"tool_call_id": "tc2",
			"tool_call_name": "run_shell",
		}
		denial2, _ = check_guardrails(action2, ctx)
		self.assertIsNone(denial2, "Allowed command should pass in auto mode")

		with patch('secator.ai.actions.subprocess.run') as mock_subprocess:
			mock_subprocess.return_value = MagicMock(stdout="output\n", stderr="")
			results = list(dispatch_action(action2, ctx))
		self.assertTrue(any(isinstance(r, Ai) and r.ai_type == "shell_output" for r in results))

		# --- Turn 3: Stop action → exit ---
		action3 = {
			"action": "stop",
			"reason": "Scan complete",
			"tool_call_id": "tc3",
			"tool_call_name": "stop",
		}
		results3 = list(dispatch_action(action3, ctx))
		stopped = [r for r in results3 if isinstance(r, Ai) and r.ai_type == "stopped"]
		self.assertEqual(len(stopped), 1)

		# In the main loop, stop_reason would be set and loop exits
		stop_reason = stopped[0].content
		self.assertIsNotNone(stop_reason)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestLoopResilientToActionErrors(unittest.TestCase):
	"""A Python error during an action dispatch must NOT kill the main loop.

	It must be caught, turned into an Error item fed back to the LLM as that
	tool call's result, and the loop must continue.
	"""

	def test_safe_dispatch_catches_exception_and_feeds_back(self):
		"""safe_dispatch_action converts a raised Exception into an Error item
		carrying the action's tool_call_id, instead of propagating."""
		from secator.ai.actions import safe_dispatch_action
		from secator.output_types import Error

		ctx = _make_ctx(interactive="auto")
		action = {
			"action": "shell",
			"command": "curl http://10.0.0.1",
			"tool_call_id": "tc_err",
			"tool_call_name": "run_shell",
		}

		# Make the shell handler raise the exact failure from the spec.
		def _boom(*a, **k):
			raise TypeError("'str' object is not a mapping")

		with patch("secator.ai.actions._handle_shell", _boom):
			# Must NOT raise.
			results = list(safe_dispatch_action(action, ctx))

		errors = [r for r in results if isinstance(r, Error)]
		self.assertEqual(len(errors), 1, "expected exactly one Error item")
		err = errors[0]
		# LLM-facing feedback phrasing + the exception type/message.
		self.assertIn("Action failed with error", err.message)
		self.assertIn("TypeError", err.message)
		self.assertIn("'str' object is not a mapping", err.message)
		self.assertIn("try again", err.message.lower())
		# Attributed to the failing tool call so it groups into that tool result.
		self.assertEqual(err._context.get("tool_call_id"), "tc_err")
		self.assertEqual(err._context.get("tool_call_name"), "run_shell")

	def test_does_not_catch_keyboardinterrupt(self):
		"""Control-flow exceptions (BaseException) must propagate, not be swallowed."""
		from secator.ai.actions import safe_dispatch_action

		ctx = _make_ctx(interactive="auto")
		action = {"action": "shell", "command": "x", "tool_call_id": "tc", "tool_call_name": "run_shell"}

		def _interrupt(*a, **k):
			raise KeyboardInterrupt()
			yield  # pragma: no cover - make it a generator

		with patch("secator.ai.actions._handle_shell", _interrupt):
			with self.assertRaises(KeyboardInterrupt):
				list(safe_dispatch_action(action, ctx))

	def test_dispatch_and_collect_continues_and_feeds_history(self):
		"""Drive the real _dispatch_and_collect: a raising action yields an Error,
		appends an error result to history (LLM-visible), and does NOT raise."""
		from secator.tasks.ai import ai as AiTask
		from secator.output_types import Error

		tool_results = []  # (name, tc_id, content) tuples appended to history

		class _FakeHistory:
			def get_action_budget(self, model):
				return 10000

			def add_tool_result(self, name, tc_id, content):
				tool_results.append((name, tc_id, content))

		persisted = []
		fake_self = MagicMock()
		fake_self.backend = CLIBackend()
		fake_self.session_id = "sess-err"
		fake_self.model = "test-model"
		fake_self.reports_folder = None
		fake_self.encryptor = None
		fake_self.history = _FakeHistory()
		fake_self.add_result = lambda item, **kw: persisted.append(item)

		ctx = MagicMock()
		ctx.results = []

		action = {
			"action": "shell",
			"command": "curl http://10.0.0.1",
			"tool_call_id": "tc_err",
			"tool_call_name": "run_shell",
		}

		def _boom(*a, **k):
			raise TypeError("'str' object is not a mapping")
			yield  # pragma: no cover

		with patch("secator.ai.actions._handle_shell", _boom):
			# Single action → safe_dispatch_action path. Must not raise.
			gen = AiTask._dispatch_and_collect(fake_self, [action], ctx)
			yielded = list(gen)

		# An Error item was yielded to the caller (visible in console / persisted).
		errors = [r for r in yielded if isinstance(r, Error)]
		self.assertEqual(len(errors), 1)

		# The error reached the LLM-visible history as this tool call's result.
		self.assertEqual(len(tool_results), 1)
		name, tc_id, content = tool_results[0]
		self.assertEqual(tc_id, "tc_err")
		self.assertIn("error", content.lower())
		self.assertIn("'str' object is not a mapping", content)


# =============================================================================
# Mid-flight steering: _drain_steers injects pending steers into history
# =============================================================================

@unittest.skipUnless(HAS_AI, "ai addon required")
class TestDrainSteers(unittest.TestCase):
	"""The loop's `_drain_steers` drains pending steers and injects them.

	A pending `ai_type:"steer"` doc (user message sent WHILE the agent runs) must
	be drained at the loop checkpoint, appended to the LLM history as a
	`[User interjected]: …` user message, echoed as a steer Ai item, and marked
	consumed — without breaking the loop or the existing follow-up flow.
	"""

	def _make_task(self, backend, history=None):
		"""Build a minimal `ai` task with only what _drain_steers reads."""
		from secator.tasks.ai import ai
		task = object.__new__(ai)
		task.backend = backend
		task.session_id = "steer-sess"
		task.encryptor = None
		task.history = history or ChatHistory()
		task.debug = lambda *a, **k: None
		return task

	def test_steer_drained_injected_and_consumed(self):
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = [
			{"content": "actually focus on the API", "_timestamp": 1},
		]
		mock_engine.update = MagicMock()
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)
		task = self._make_task(backend)

		yielded = list(task._drain_steers())

		# Injected into history as a user "interjected" message.
		user_msgs = [m for m in task.history.to_messages() if m["role"] == "user"]
		self.assertEqual(len(user_msgs), 1)
		self.assertEqual(user_msgs[-1]["content"], "[User interjected]: actually focus on the API")

		# Echoed as a steer Ai item carrying the session_id (so it persists).
		steer_items = [r for r in yielded if isinstance(r, Ai) and r.ai_type == "steer"]
		self.assertEqual(len(steer_items), 1)
		self.assertEqual(steer_items[0].content, "actually focus on the API")
		self.assertEqual(steer_items[0].session_id, "steer-sess")

		# Marked consumed so it injects exactly once.
		update_set = mock_engine.update.call_args[0][1]
		self.assertEqual(update_set["$set"]["status"], "consumed")

	def test_no_steer_is_noop_and_preserves_loop(self):
		"""No pending steer -> nothing injected, history untouched (loop intact)."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.return_value = []
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)
		history = ChatHistory()
		history.add_user("original prompt")
		task = self._make_task(backend, history=history)

		yielded = list(task._drain_steers())

		self.assertEqual(yielded, [])
		user_msgs = [m for m in task.history.to_messages() if m["role"] == "user"]
		self.assertEqual([m["content"] for m in user_msgs], ["original prompt"])

	def test_non_remote_backend_is_noop(self):
		"""Local/auto backends have no channel -> drain is a no-op (no crash)."""
		task = self._make_task(create_backend("auto"))
		self.assertEqual(list(task._drain_steers()), [])

	def test_steer_poll_error_never_crashes_loop(self):
		"""A backend error during drain is swallowed (run must not crash)."""
		from secator.ai.interactivity import RemoteBackend
		mock_engine = MagicMock()
		mock_engine.search.side_effect = RuntimeError("mongo down")
		backend = RemoteBackend(timeout=60, query_engine=mock_engine, poll_interval=0.01)
		task = self._make_task(backend)
		# Should not raise, yields nothing, history untouched.
		self.assertEqual(list(task._drain_steers()), [])
		self.assertEqual(task.history.to_messages(), [])


if __name__ == "__main__":
	unittest.main()
