"""Exhaustive AI permission/guardrail decision matrix.

Locks the DECISION CONTRACT down: for every (mode, isolated, action, scope) cell we
assert the VERDICT, the PROMPT COUNT and the BACKEND-CALL COUNT — not just "allowed
or not". Two named regressions reproduce the canary root causes:

- test_regression_isolated_compound_command_no_spin — RC1: isolated + an unparseable
compound shell command must resolve to allow in ONE round with zero prompts (was: a
5-round spin then a bare deny).
- test_regression_isolated_ip_from_in_scope_hostname — RC2: isolated, an in-scope
hostname resolved to its IP, target given as that IP -> allow, 0 prompts.
"""
import unittest
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED

HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.ai.actions import ActionContext, check_guardrails_sync, check_guardrails
	from secator.ai.guardrails import PermissionEngine
	from secator.ai.interactivity import CLIBackend, AutoBackend, RemoteBackend, UserInputTimeout
	from secator.output_types import Ai
	from secator.scope import resolve_scope_hostnames
else:  # placeholders so class defs below still import when the ai addon is absent (tests skip)
	CLIBackend = AutoBackend = RemoteBackend = object
	UserInputTimeout = Exception


# --- spy backends: count ask_user() / pending prompts, keep isinstance semantics ---

class SpyCLI(CLIBackend):
	"""Local backend that records prompts and answers with a canned decision."""
	def __init__(self, answer="deny"):
		self.ask_calls = 0
		self._answer = answer

	def ask_user(self, *a, **k):
		self.ask_calls += 1
		return {"answer": self._answer}


class SpyAuto(AutoBackend):
	def __init__(self):
		self.ask_calls = 0

	def ask_user(self, *a, **k):
		self.ask_calls += 1
		return None  # AutoBackend: no human -> not run


class _FakeQE:
	"""Query engine that never returns an answer -> remote poll times out."""
	def search(self, *a, **k):
		return []

	def update(self, *a, **k):
		return None


ACTIONS = {
	"shell-simple": {"action": "shell", "command": "whoami"},
	# Genuinely unparseable compound command (unbalanced quote) -> _parse_subcommands
	# returns [] -> the "Could not parse" ask. This is RC1's trigger condition.
	"shell-compound": {"action": "shell", "command": 'for i in 1 2; do echo "$i; done'},
	"path": {"action": "shell", "command": "cat /etc/shadow"},
}


def _engine(in_scope=None, out_of_scope=None):
	cfg = {
		"allow": ["shell(curl,cat,ls)"],
		"deny": [],
		"ask": ["target(*)", "read(*)", "write(*)"],
	}
	return PermissionEngine(cfg, targets=[], workspace="/tmp/ws", in_scope=in_scope, out_of_scope=out_of_scope)


def _ctx(engine, backend, isolated):
	return ActionContext(
		targets=[], model="m", permission_engine=engine, backend=backend,
		isolated=isolated, session_id="s", context={"run_id": "r1"},
	)


def _guard(action, *, isolated, backend, engine=None, in_scope=None, out_of_scope=None, hard_deny=False):
	from secator.config import CONFIG
	engine = engine or _engine(in_scope, out_of_scope)
	ctx = _ctx(engine, backend, isolated)
	with patch.object(CONFIG.security, "scope_hard_deny", hard_deny):
		denial, items = check_guardrails_sync(action, ctx)
	pending = [i for i in items if isinstance(i, Ai) and getattr(i, "status", "") == "pending"]
	return denial, len(pending)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestIsolatedAlwaysAllowsShellAndPath(unittest.TestCase):
	"""isolated + shell/path -> ALWAYS allow, in EVERY mode, 0 prompts, 0 backend calls."""

	def _assert_isolated_allow(self, action_key):
		for backend in (SpyCLI(), SpyAuto()):
			denial, pending = _guard(ACTIONS[action_key], isolated=True, backend=backend)
			self.assertIsNone(denial, f"{action_key}/{type(backend).__name__}: {denial}")
			self.assertEqual(backend.ask_calls, 0, f"{action_key}: prompted in isolated mode")
			self.assertEqual(pending, 0)
		# remote too
		rb = RemoteBackend(timeout=0, poll_interval=0, query_engine=_FakeQE())
		denial, pending = _guard(ACTIONS[action_key], isolated=True, backend=rb)
		self.assertIsNone(denial)
		self.assertEqual(pending, 0)

	def test_isolated_shell_simple(self):
		self._assert_isolated_allow("shell-simple")

	def test_isolated_shell_compound_unparseable(self):
		self._assert_isolated_allow("shell-compound")

	def test_isolated_path(self):
		self._assert_isolated_allow("path")


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestIsolatedTargetScope(unittest.TestCase):
	"""Target/scope decisions are UNAFFECTED by isolation."""

	def test_isolated_target_in_scope_direct(self):
		denial, pending = _guard(
			{"action": "shell", "command": "curl http://10.0.0.1/"},
			isolated=True, backend=SpyCLI(), in_scope=["10.0.0.1"],
		)
		self.assertIsNone(denial)
		self.assertEqual(pending, 0)

	def test_isolated_target_in_scope_ip_from_hostname(self):
		with patch("socket.getaddrinfo", return_value=[(None, None, None, "", ("34.118.235.207", 0))]):
			scope = resolve_scope_hostnames(["vuln-apache.testlab.svc.cluster.local"])
		self.assertIn("34.118.235.207", scope)
		denial, pending = _guard(
			{"action": "shell", "command": "curl http://34.118.235.207/"},
			isolated=True, backend=SpyCLI(), in_scope=scope,
		)
		self.assertIsNone(denial)
		self.assertEqual(pending, 0)

	def test_isolated_target_in_scope_wildcard_host(self):
		denial, pending = _guard(
			{"action": "shell", "command": "curl http://api.acme.com/"},
			isolated=True, backend=SpyCLI(), in_scope=["*.acme.com"],
		)
		self.assertIsNone(denial)
		self.assertEqual(pending, 0)

	def test_isolated_target_out_of_scope_hard_deny(self):
		denial, pending = _guard(
			{"action": "shell", "command": "curl http://9.9.9.9/"},
			isolated=True, backend=SpyCLI(), in_scope=["10.0.0.1"], hard_deny=True,
		)
		self.assertIsNotNone(denial)
		self.assertIn("out_of_scope", denial)
		self.assertIn("9.9.9.9", denial)
		self.assertEqual(pending, 0)

	def test_isolated_target_out_of_scope_soft_asks_local(self):
		# hard_deny OFF -> a live ask remains (isolation never auto-allows a target).
		backend = SpyCLI(answer="deny")
		denial, _ = _guard(
			{"action": "shell", "command": "curl http://9.9.9.9/"},
			isolated=True, backend=backend, in_scope=["10.0.0.1"], hard_deny=False,
		)
		self.assertIsNotNone(denial)          # user denied
		self.assertEqual(backend.ask_calls, 1)  # exactly one prompt


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestNonIsolatedModes(unittest.TestCase):

	def test_local_shell_unparseable_prompts_exactly_once(self):
		# RC1's non-isolated sibling: parse-failure must prompt ONCE, never spin to 5.
		backend = SpyCLI(answer="allow")
		denial, _ = _guard(ACTIONS["shell-compound"], isolated=False, backend=backend)
		self.assertIsNone(denial)             # approved
		self.assertEqual(backend.ask_calls, 1)

	def test_local_shell_unparseable_denied_once(self):
		backend = SpyCLI(answer="deny")
		denial, _ = _guard(ACTIONS["shell-compound"], isolated=False, backend=backend)
		self.assertIsNotNone(denial)
		self.assertEqual(backend.ask_calls, 1)  # one prompt, not a 5-round spin

	def test_auto_ask_returns_none_no_spin(self):
		for key in ("shell-simple", "shell-compound", "path"):
			backend = SpyAuto()
			denial, _ = _guard(ACTIONS[key], isolated=False, backend=backend)
			self.assertIsNotNone(denial, key)
			self.assertNotIn("unresolved after", denial, f"{key}: spun to the N-prompt deny")
			self.assertLessEqual(backend.ask_calls, 1, key)

	def test_auto_target_out_of_scope_soft_fails_closed(self):
		backend = SpyAuto()
		denial, _ = _guard(
			{"action": "shell", "command": "curl http://9.9.9.9/"},
			isolated=False, backend=backend, in_scope=["10.0.0.1"], hard_deny=False,
		)
		self.assertIsNotNone(denial)          # None from ask_user -> not run

	def test_remote_ask_yields_one_pending_then_times_out(self):
		# 1 pending prompt then timeout: the prompt is LEFT pending (UserInputTimeout
		# unwinds the loop), never auto-denied.
		rb = RemoteBackend(timeout=0, poll_interval=0, query_engine=_FakeQE())
		engine = _engine()
		ctx = _ctx(engine, rb, isolated=False)
		gen = check_guardrails(ACTIONS["shell-simple"], ctx)
		first = next(gen)
		self.assertIsInstance(first, Ai)
		self.assertEqual(first.status, "pending")
		with self.assertRaises(UserInputTimeout):
			next(gen)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestCheckerExceptionIsDeterministic(unittest.TestCase):
	"""ANY exception in the checker resolves to a deterministic verdict, never a spin."""

	def test_isolated_shell_exception_allows(self):
		engine = _engine()
		backend = SpyCLI()
		ctx = _ctx(engine, backend, isolated=True)
		with patch.object(engine, "check_action", side_effect=RuntimeError("boom")):
			denial, _ = check_guardrails_sync(ACTIONS["shell-simple"], ctx)
		self.assertIsNone(denial)             # sandbox is the boundary
		self.assertEqual(backend.ask_calls, 0)

	def test_non_isolated_exception_fails_closed_no_spin(self):
		engine = _engine()
		backend = SpyAuto()
		ctx = _ctx(engine, backend, isolated=False)
		with patch.object(engine, "check_action", side_effect=RuntimeError("boom")):
			denial, _ = check_guardrails_sync(ACTIONS["shell-simple"], ctx)
		self.assertIsNotNone(denial)
		self.assertNotIn("unresolved after", denial)
		self.assertEqual(backend.ask_calls, 0)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestFollowUpNotSuppressedByIsolation(unittest.TestCase):
	"""single/multi-choice follow_up is NOT a permission gate: it passes through in
	every mode, including isolated."""

	def test_follow_up_passes_in_isolated(self):
		denial, pending = _guard(
			{"action": "follow_up", "reason": "pick one", "choices": ["a", "b"], "multiple": False},
			isolated=True, backend=SpyAuto(),
		)
		self.assertIsNone(denial)


@unittest.skipUnless(HAS_AI, "ai addon required")
class TestCanaryRegressions(unittest.TestCase):

	def test_regression_isolated_compound_command_no_spin(self):
		"""RC1: a compound `for..do..done` command the shell parser cannot parse (the
		canary condition — here an unparseable for-loop, so _parse_subcommands -> [] and
		no target is extracted), isolated -> allow, 0 prompts, no 5-round spin-deny."""
		from secator.ai.guardrails import _parse_subcommands, extract_command_targets
		cmd = 'for dir in a b c; do curl $dir; done "x'  # unbalanced quote -> unparseable for-loop
		self.assertEqual(_parse_subcommands(cmd), [])           # parser genuinely fails
		self.assertEqual(extract_command_targets(cmd), [])      # so no target is extracted either
		action = {"action": "shell", "command": cmd}
		for backend in (SpyCLI(), SpyAuto()):
			denial, pending = _guard(action, isolated=True, backend=backend)
			self.assertIsNone(denial, f"{type(backend).__name__}: {denial}")
			self.assertEqual(backend.ask_calls, 0)
			self.assertEqual(pending, 0)

	def test_regression_isolated_ip_from_in_scope_hostname(self):
		"""RC2: in_scope hostname resolves to an IP; target given as that IP -> allow."""
		with patch("socket.getaddrinfo", return_value=[(None, None, None, "", ("34.118.235.207", 0))]):
			scope = resolve_scope_hostnames(["vuln-apache.testlab.svc.cluster.local"])
		backend = SpyCLI()
		denial, pending = _guard(
			{"action": "shell", "command": "curl http://34.118.235.207/"},
			isolated=True, backend=backend, in_scope=scope,
		)
		self.assertIsNone(denial)
		self.assertEqual(backend.ask_calls, 0)
		self.assertEqual(pending, 0)


if __name__ == "__main__":
	unittest.main()
