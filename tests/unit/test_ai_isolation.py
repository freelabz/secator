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
	engine = PermissionEngine(_config(), targets=["10.0.0.1"], workspace="/tmp/ws")
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


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestChildInheritsIsolated(unittest.TestCase):
	"""A spawned child force-inherits the parent's `isolated` and can never lower it."""

	def test_child_inherits_parent_isolated_true(self):
		from secator.ai.actions import _child_run_opts
		self.assertTrue(_child_run_opts(_ctx(isolated=True))["isolated"])

	def test_child_inherits_parent_isolated_false(self):
		from secator.ai.actions import _child_run_opts
		self.assertFalse(_child_run_opts(_ctx(isolated=False))["isolated"])

	def test_llm_cannot_set_isolated_on_child(self):
		from secator.ai.utils import _sanitize_child_opts
		# An LLM-supplied `isolated` is stripped before it can reach the child run_opts.
		self.assertNotIn("isolated", _sanitize_child_opts({"isolated": False, "ports": "80"}))

	def test_child_cannot_lower_isolated(self):
		# Parent is isolated; LLM tries isolated=False. After sanitize + the real merge order
		# used in _run_runner ({**_child_run_opts(ctx), **llm_opts}), isolation stays True.
		from secator.ai.actions import _child_run_opts
		from secator.ai.utils import _sanitize_child_opts
		llm_opts = _sanitize_child_opts({"isolated": False})
		run_opts = {**_child_run_opts(_ctx(isolated=True)), **llm_opts}
		self.assertTrue(run_opts["isolated"])


if __name__ == '__main__':
	unittest.main()
