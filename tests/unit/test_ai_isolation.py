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


class _CP:
	def __init__(self, rc=0, out="", err=""):
		self.returncode, self.stdout, self.stderr = rc, out, err


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestSandboxCreateRace(unittest.TestCase):
	"""`_ensure_sandbox_container` must survive the create race and surface real errors."""

	def test_run_collision_uses_existing_container(self):
		from secator.ai import actions as A
		ctx = _ctx(isolated=True)
		context = {"run_id": "r-race"}
		# inspect: initial=false, under-lock=false, post-run-failure=true (a racer won).
		inspects = iter(["false", "false", "true"])

		def fake_run(argv, **kw):
			if argv[:2] == ["docker", "inspect"]:
				return _CP(0, next(inspects))
			if argv[:2] == ["docker", "run"]:
				return _CP(1, "", "Conflict. The container name is already in use")
			return _CP(0)

		with patch("subprocess.run", side_effect=fake_run):
			name = A._ensure_sandbox_container(ctx, context)
		self.assertEqual(name, A._sandbox_container_name(ctx, context))

	def test_run_failure_surfaces_stderr(self):
		from secator.ai import actions as A
		ctx = _ctx(isolated=True)
		context = {"run_id": "r-err"}
		inspects = iter(["false", "false", "false"])  # never comes up

		def fake_run(argv, **kw):
			if argv[:2] == ["docker", "inspect"]:
				return _CP(0, next(inspects))
			if argv[:2] == ["docker", "run"]:
				return _CP(125, "", "docker: Error response from daemon: no space left on device")
			return _CP(0)

		with patch("subprocess.run", side_effect=fake_run):
			with self.assertRaises(RuntimeError) as cm:
				A._ensure_sandbox_container(ctx, context)
		self.assertIn("no space left on device", str(cm.exception))


if __name__ == '__main__':
	unittest.main()
