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
	from secator.ai.actions import ActionContext, check_guardrails_sync as check_guardrails, dispatch_action
	from secator.ai.tools._sandbox import _wrap_docker_exec
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
		with patch('secator.ai.tools.run_shell._ensure_sandbox_container', return_value="sbx-r123") as ensure, \
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
		from secator.ai.tools import _sandbox as A
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
		from secator.ai.tools import _sandbox as A
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


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestSandboxStartAndBootstrap(unittest.TestCase):
	"""Sandbox start overrides the image entrypoint; base packages use the image's package manager."""

	def _create(self, pm="apk", install_rc=0, running_after_start=True):
		from secator.ai.tools import _sandbox as A
		calls = []
		inspects = iter(["false", "false", "true" if running_after_start else "false"])

		def fake_run(argv, **kw):
			calls.append(argv)
			if argv[:2] == ["docker", "inspect"]:
				return _CP(0, next(inspects))
			if argv[:2] == ["docker", "exec"] and "command -v" in argv[-1]:
				return _CP(0 if pm else 1, f"{pm}\n" if pm else "")
			if argv[:2] == ["docker", "exec"] and "/etc/gai.conf" not in argv[-1]:
				return _CP(install_rc, "", "ERROR: unable to select packages" if install_rc else "")
			return _CP(0)

		pkgs = patch.object(A, "_SANDBOX_PACKAGES", "git curl python3-pip")
		with patch("subprocess.run", side_effect=fake_run), patch("secator.rich.console.print") as printed, pkgs:
			name = A._ensure_sandbox_container(_ctx(isolated=True), {"run_id": "r-boot"})
		installs = [c for c in calls if c[:2] == ["docker", "exec"] and "command -v" not in c[-1]
		            and "/etc/gai.conf" not in c[-1]]
		return name, calls, installs, printed

	def test_work_dir_is_made_writable_as_root(self):
		_, calls, _, _ = self._create()
		prep = next(c for c in calls if c[:2] == ["docker", "exec"] and "/etc/gai.conf" in c[-1])
		self.assertEqual(prep[2:4], ["-u", "0"])
		self.assertIn("chmod 1777 /work", prep[-1])

	def test_dead_container_warns_with_the_exec_error(self):
		from secator.ai.tools import _sandbox as A

		def fake_run(argv, **kw):
			return _CP(1, "", "Error response from daemon: container abc is not running")

		with patch("subprocess.run", side_effect=fake_run), patch("secator.rich.console.print") as printed:
			A._install_base_packages("sbx-x")
		self.assertIn("is not running", printed.call_args[0][0].message)

	def test_entrypoint_is_overridden_to_keep_alive(self):
		_, calls, _, _ = self._create()
		run = next(c for c in calls if c[:2] == ["docker", "run"])
		i = run.index("--entrypoint")
		self.assertEqual(run[i + 1], "sleep")
		self.assertEqual(run[-1], "infinity")
		self.assertNotIn("sleep", run[i + 2:])

	def test_container_exiting_after_start_is_an_error(self):
		with self.assertRaises(RuntimeError) as cm:
			self._create(running_after_start=False)
		self.assertIn("exited right after start", str(cm.exception))

	def test_alpine_uses_apk_with_mapped_names_as_root(self):
		_, _, installs, printed = self._create(pm="apk")
		self.assertEqual(len(installs), 1)
		self.assertEqual(installs[0][2:4], ["-u", "0"])
		self.assertIn("apk add --no-cache -q git curl py3-pip", installs[0][-1])
		printed.assert_not_called()

	def test_debian_uses_apt_get(self):
		_, _, installs, _ = self._create(pm="apt-get")
		self.assertIn("apt-get -o Acquire::ForceIPv4=true install", installs[0][-1])
		self.assertIn("python3-pip", installs[0][-1])

	def test_dnf_is_supported(self):
		_, _, installs, _ = self._create(pm="dnf")
		self.assertIn("dnf install -y -q git curl python3-pip", installs[0][-1])

	def test_no_package_manager_warns(self):
		name, _, installs, printed = self._create(pm="")
		self.assertTrue(name)
		self.assertEqual(installs, [])
		self.assertIn("no supported package manager", printed.call_args[0][0].message)

	def test_failed_install_warns_but_sandbox_is_usable(self):
		name, _, _, printed = self._create(pm="apk", install_rc=1)
		self.assertTrue(name)
		msg = printed.call_args[0][0].message
		self.assertIn("apk exited 1", msg)
		self.assertIn("unable to select packages", msg)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestChildInheritsIsolated(unittest.TestCase):
	"""A spawned child force-inherits the parent's `isolated` and can never lower it."""

	def test_child_inherits_parent_isolated_true(self):
		from secator.ai.tools._runner import _child_run_opts
		self.assertTrue(_child_run_opts(_ctx(isolated=True))["isolated"])

	def test_child_inherits_parent_isolated_false(self):
		from secator.ai.tools._runner import _child_run_opts
		self.assertFalse(_child_run_opts(_ctx(isolated=False))["isolated"])

	def test_llm_cannot_set_isolated_on_child(self):
		from secator.ai.utils import _sanitize_child_opts
		# An LLM-supplied `isolated` is stripped before it can reach the child run_opts.
		self.assertNotIn("isolated", _sanitize_child_opts({"isolated": False, "ports": "80"}))

	def test_child_cannot_lower_isolated(self):
		# Parent is isolated; LLM tries isolated=False. After sanitize + the real merge order
		# used in _run_runner ({**_child_run_opts(ctx), **llm_opts}), isolation stays True.
		from secator.ai.tools._runner import _child_run_opts
		from secator.ai.utils import _sanitize_child_opts
		llm_opts = _sanitize_child_opts({"isolated": False})
		run_opts = {**_child_run_opts(_ctx(isolated=True)), **llm_opts}
		self.assertTrue(run_opts["isolated"])

	def test_ai_subagent_inherits_parent_dangerous(self):
		# An AI subagent INHERITS the parent's operator-chosen dangerous (so a bypass the
		# operator enabled extends to the exploit work it delegates — otherwise the subagent
		# is Blocked on the very actions the operator opted into). dangerous is user-only
		# (agent-readonly + stripped from LLM child opts), so the LLM still can't escalate.
		from secator.ai.actions import ActionContext
		from secator.ai.tools._runner import _child_dangerous
		self.assertTrue(_child_dangerous(ActionContext(targets=["x"], model="m", dangerous=True),
		                                 is_ai_subagent=True))
		self.assertFalse(_child_dangerous(ActionContext(targets=["x"], model="m", dangerous=False),
		                                  is_ai_subagent=True))

	def test_non_ai_child_never_dangerous(self):
		# A task/workflow/shell child stays non-dangerous even under a dangerous parent —
		# dangerous is an ai-task concept, meaningless for them.
		from secator.ai.actions import ActionContext
		from secator.ai.tools._runner import _child_dangerous
		self.assertFalse(_child_dangerous(ActionContext(targets=["x"], model="m", dangerous=True),
		                                  is_ai_subagent=False))


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestShellNeverBlocksOnSudo(unittest.TestCase):
	"""AI-issued shell runs with tty=False so a password-requiring sudo fails fast
	(Command._prompt_sudo's non-interactive path) instead of hanging on getpass."""

	def test_handle_shell_forces_tty_false(self):
		ctx = _ctx(isolated=False)
		# `ls` is in the allow-list so _handle_shell actually runs; tty=False is set for
		# every AI shell command (it's what makes a sudo command fail fast rather than hang).
		action = {"action": "shell", "command": "ls -la"}
		with patch('secator.tasks.command.command') as mock_cmd:
			fake = mock_cmd.return_value
			fake.output = "done"
			fake.id = "task_fake"
			list(dispatch_action(action, ctx))
		self.assertIs(mock_cmd.call_args.kwargs.get("tty"), False)


if __name__ == '__main__':
	unittest.main()
