"""`--isolated` run_shell sandbox (gVisor+DinD Path A).

Covers the two behavioral guarantees of isolated mode, without any real Docker:
- guardrails: path + command asks are dropped, network-target asks remain;
- `_handle_shell`: the command is routed through `docker exec` into the per-runner container,
while the transcript still shows the original command.
"""
import unittest
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED
HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.actions import (
		ActionContext, check_guardrails_sync as check_guardrails, dispatch_action,
		_wrap_docker_exec,
	)
	from secator.ai.guardrails import PermissionEngine
	from secator.ai.interactivity import create_backend
	from secator.output_types import Ai


def _config():
	# curl is allowed; no allowed paths/targets beyond 10.0.0.1 → everything else is "ask".
	return {"allow": ["target(10.0.0.1)", "shell(curl,cat,ls)"], "deny": [], "ask": []}


def _ctx(isolated, backend="auto"):
	# The engine owns the isolation verdict now (isolated shell/path -> allow), so thread
	# it in at build time — the caller no longer post-processes for isolation.
	engine = PermissionEngine(_config(), targets=["10.0.0.1"], workspace="/tmp/ws", isolated=isolated)
	return ActionContext(
		targets=["10.0.0.1"], model="m", interactive=backend, backend=create_backend(backend),
		session_id="s", permission_engine=engine, isolated=isolated,
		context={"run_id": "r123"},
	)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestIsolatedGuardrails(unittest.TestCase):

	def test_shell_and_path_asks_dropped_when_isolated(self):
		# Unknown command + a non-allowed path. Auto backend blocks any ASK.
		action = {"action": "shell", "command": "unknowncmd /etc/shadow"}
		# Baseline: not isolated → the shell/path ask is blocked (denied) in auto mode.
		denial, _ = check_guardrails(action, _ctx(isolated=False))
		self.assertIsNotNone(denial)
		# Isolated → shell + path asks dropped → allowed.
		denial, _ = check_guardrails(action, _ctx(isolated=True))
		self.assertIsNone(denial, f"isolated should drop shell/path asks, got: {denial}")

	def test_target_asks_remain_when_isolated(self):
		# curl is allowed (no shell ask); 9.9.9.9 is NOT an allowed target → target ask.
		action = {"action": "shell", "command": "curl http://9.9.9.9/"}
		denial, _ = check_guardrails(action, _ctx(isolated=True))
		self.assertIsNotNone(denial)                 # target prompt still enforced
		self.assertIn("9.9.9.9", denial)

	def test_isolated_target_check_error_fails_closed(self):
		# A fault in the TARGET layer (network egress) must fail CLOSED even under isolation
		# — isolation drops only the shell/path layers, never targets. Force _check_values to
		# raise and assert the verdict is deny (not the isolated-shell allow). CodeRabbit CWE-863.
		eng = PermissionEngine(_config(), targets=["10.0.0.1"], workspace="/tmp/ws", isolated=True)
		with patch.object(eng, "_check_values", side_effect=ValueError("boom")):
			res = eng.check_action({"action": "shell", "command": "curl http://9.9.9.9/"})
		self.assertEqual(res.decision, "deny")
		self.assertIn("fail-closed", res.reason)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestIsolatedShellRouting(unittest.TestCase):

	def test_wrap_docker_exec_is_quoting_safe(self):
		wrapped = _wrap_docker_exec("sbx-r123", "echo 'a b' && ls $HOME")
		self.assertTrue(wrapped.startswith("docker exec sbx-r123 sh -lc "))
		self.assertIn("base64 -d | sh", wrapped)     # command carried as base64, not inline

	def test_handle_shell_execs_in_container_but_transcript_shows_original(self):
		ctx = _ctx(isolated=True)
		action = {"action": "shell", "command": "id && whoami"}
		with patch('secator.ai.actions._ensure_sandbox_container', return_value="sbx-r123") as ensure, \
		     patch('secator.tasks.command.command') as mock_cmd:
			fake = mock_cmd.return_value
			fake.output = "uid=0"
			fake.id = "task_fake"
			results = list(dispatch_action(action, ctx))

		ensure.assert_called_once()                                  # sandbox container spawned
		ran = mock_cmd.call_args.args[0][0]                          # CommandTask([exec_command], ...)
		self.assertTrue(ran.startswith("docker exec sbx-r123 "), f"not routed to container: {ran}")
		shell_docs = [r for r in results if isinstance(r, Ai) and r.ai_type == "shell"]
		self.assertEqual(shell_docs[0].content, "id && whoami")      # transcript shows the ORIGINAL
		self.assertTrue(any(isinstance(r, Ai) and r.ai_type == "shell_output" for r in results))


if __name__ == '__main__':
	unittest.main()
