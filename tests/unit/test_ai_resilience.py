"""Resiliency harness: fake the LLM and feed the agent loop every kind of weird
response, asserting the invariant that a malformed LLM response is handled
**turn-locally** and the loop **survives and continues** — never aborts the whole
session via the top-level catch-all, and never raises out of the loop.

Why "survives and continues" and not just "doesn't crash": `_run_loop` already
wraps each iteration in `try/except Exception -> Error.from_exception; return`
(ai.py). So an unhandled exception won't kill the worker — but it ABORTS the
entire conversation. The resilient path instead rejects the bad tool call as a
clean tool-result error (so the model can retry) and keeps looping. We detect the
difference by counting `call_llm` invocations: a tool-call turn that is handled
turn-locally forces another iteration (the loop asks the model again), so
`call_llm` is called at least twice. An abort stops at one.

Two layers:
  1. TestWeirdToolCalls  — a curated table (regression coverage for the bugs we've
     hit + adjacent ones: stringified opts/query, broken JSON, wrong-type args,
     unknown tools, missing fields, mixed batches, ...).
  2. TestMalformedArgFuzzer — random malformed tool-call arguments across all
     tools; seeded so any failure reproduces.
"""
import contextlib
import json
import random
import types
import unittest
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED

HAS_AI = ADDONS_ENABLED.get('ai', False)

if HAS_AI:
	from secator.tasks.ai import ai
	from secator.ai.history import ChatHistory
	from secator.ai.interactivity import create_backend
	from secator.output_types import Error


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _tc(name, args, call_id="tc1"):
	"""A litellm-shaped tool_call. ``args`` may be a dict/list (JSON-dumped, the
	normal case) or a raw string — pass a string to inject malformed/weird
	arguments verbatim, exactly as a misbehaving model would."""
	arguments = json.dumps(args) if isinstance(args, (dict, list)) else args
	return types.SimpleNamespace(id=call_id, function=types.SimpleNamespace(name=name, arguments=arguments))


def _resp(content=None, tool_calls=None, usage="default", finish_reason=None):
	"""A call_llm() return dict."""
	if usage == "default":
		usage = {"tokens": 100, "cost": 0.001}
	return {"content": content, "tool_calls": tool_calls or [], "usage": usage,
			"finish_reason": finish_reason}


def _make_loop_task():
	"""A bare `ai` task carrying exactly the state `_run_loop` reads, with
	dry_run+dangerous so actions neither execute real tools nor need the guardrail
	shell parser — this isolates arg-handling / dispatch resilience."""
	task = ai.__new__(ai)
	task.context = {"ai_tokens": 0, "ai_prompt_tokens": 0, "ai_completion_tokens": 0, "ai_cost": 0.0}
	task.history = ChatHistory()
	task.inputs = []
	task.model = "test-model"
	task.intent_model = "test-model"
	task.temp = 0.7
	task.api_base = None
	task.api_key = "key"
	task.max_iterations = 6
	task.max_tokens_total = 100000
	task.max_workers = 1
	task.is_subagent = True
	task.verbose = False
	task.dry_run = True
	task.mode = "chat"
	task.scope = "workspace"   # + empty workspace_id -> query short-circuits, no real search
	task._view = lambda *a, **kw: []  # results property reads _view()
	task.in_scope = []
	task.out_of_scope = []
	task.encryptor = None
	task.tool_schemas = []
	task.permission_engine = None
	task.dangerous = True
	task.interactive = "auto"
	task._sync = True
	task.session_id = "s"
	task.async_tasks = False
	task.context_warnings = False
	task._reports_folder = None
	task.system_prompt = "SYS"
	task.debug = lambda *a, **k: None
	task.add_result = lambda *a, **k: None
	task.print_item = False
	task.print_line = False
	task.backend = create_backend("auto")
	return task


@contextlib.contextmanager
def _driven(task, weird_responses):
	"""Patch call_llm to emit the weird responses, then a terminating content-only
	response forever; stub the heavy collaborators; and capture the loop's
	top-level abort signal.

	The abort signal is `Error.from_exception`, which `_run_loop` calls at exactly
	one site (ai.py) — its `except Exception -> Error.from_exception(e); return`
	catch-all. `safe_dispatch_action` (per-action resilience) uses plain `Error(...)`,
	not `from_exception`, and `stop`/`follow_up` end the loop without raising — so a
	captured `from_exception` means an UNHANDLED exception aborted the session: a
	resilience failure, distinct from a clean end."""
	seq = list(weird_responses)
	state = {"calls": 0, "aborted_with": None}

	def _next(*a, **k):
		state["calls"] += 1
		return seq.pop(0) if seq else _resp(content="__done__", tool_calls=[])

	real_from_exc = Error.from_exception

	def _capture(exc, *a, **k):
		state["aborted_with"] = exc
		return real_from_exc(exc, *a, **k)

	with contextlib.ExitStack() as stack:
		stack.enter_context(patch('secator.tasks.ai.call_llm', side_effect=_next))
		# empty-response retries back off with time.sleep — make it instant in tests
		stack.enter_context(patch('secator.tasks.ai.time.sleep'))
		stack.enter_context(patch('secator.tasks.ai.get_context_window', return_value=8000))
		stack.enter_context(patch('secator.ai.history.get_context_window', return_value=8000))
		stack.enter_context(patch('secator.tasks.ai.save_history'))
		stack.enter_context(patch.object(type(task), 'reports_folder', property(lambda self: None)))
		stack.enter_context(patch.object(ai, '_summarize_auto', return_value=iter(())))
		stack.enter_context(patch.object(ai, '_summarize_user', return_value=iter(())))
		stack.enter_context(patch('secator.tasks.ai.Error.from_exception', side_effect=_capture))
		# content-only turns exit (no follow-up loop); tool-call turns still continue
		stack.enter_context(patch.object(ai, '_prompt_and_redetect', return_value=None))
		yield state


def _run(task, weird_responses):
	"""Drive the real _run_loop; return (yielded_items, call_count, aborted_with)."""
	with _driven(task, weird_responses) as state:
		items = list(task._run_loop())
	return items, state["calls"], state["aborted_with"]


# ---------------------------------------------------------------------------
# 1. Curated weird tool-call responses
# ---------------------------------------------------------------------------

# Each entry: (label, tool_call). The loop gets ONE turn with this tool call, then
# a terminating content turn. A resilient loop rejects/handles the bad call and
# asks the model again -> call_llm invoked >= 2.
WEIRD_TOOL_CALLS = [
	# --- stringified object/array args (provider quirk; #1273/#1275) ---
	("stringified_opts",      _tc("run_task", '{"name":"nmap","targets":["10.0.0.1"],"opts":"{\\"session_name\\":\\"x\\"}"}')),
	("stringified_query",     _tc("query_workspace", '{"query":"{\\"_type\\":\\"url\\"}"}')),
	("stringified_targets",   _tc("run_task", '{"name":"nmap","targets":"10.0.0.1"}')),
	("stringified_choices",   _tc("follow_up", '{"reason":"pick","choices":"[\\"a\\",\\"b\\"]"}')),
	# --- valid JSON, wrong shape ---
	("query_as_list",         _tc("query_workspace", {"query": ["_type", "url"]})),
	("opts_as_int",           _tc("run_task", {"name": "nmap", "targets": ["x"], "opts": 5})),
	("targets_as_number",     _tc("run_task", {"name": "nmap", "targets": 12345})),
	("args_top_level_int",    _tc("run_task", "12345")),
	("args_top_level_array",  _tc("run_task", '["nmap","10.0.0.1"]')),
	("args_top_level_string", _tc("run_task", '"just a string"')),
	# --- invalid JSON ---
	("broken_json_unbalanced", _tc("run_shell", '{"command": "curl -s x" ')),
	("broken_json_trailing",   _tc("run_task", '{"name":"nmap",}')),
	("empty_string_args",      _tc("run_shell", '')),
	("garbage_args",           _tc("run_task", 'not json at all')),
	# --- missing / empty fields ---
	("empty_object_args",     _tc("run_task", {})),
	("missing_name",          _tc("run_task", {"targets": ["x"]})),
	("shell_missing_command", _tc("run_shell", {})),
	("null_values",           _tc("run_task", {"name": None, "targets": None, "opts": None})),
	# --- unknown / nonsense tool ---
	("unknown_tool",          _tc("delete_everything", {})),
	("unknown_tool_bad_args", _tc("../../etc/passwd", 'weird')),
	# --- add_finding malformations ---
	("add_finding_str_data",  _tc("add_finding", {"finding_type": "vulnerability", "data": "not-a-dict"})),
	("add_finding_no_type",   _tc("add_finding", {"data": {"name": "x"}})),
	# --- deep nesting / large ---
	("deeply_nested_opts",    _tc("run_task", {"name": "nmap", "targets": ["x"], "opts": {"a": {"b": {"c": {"d": 1}}}}})),
]


@unittest.skipUnless(HAS_AI, 'ai addon required')
class TestWeirdToolCalls(unittest.TestCase):
	"""A malformed tool call must be handled turn-locally and the loop must
	SURVIVE and continue (call_llm invoked again), never abort the session."""

	def _assert_survives(self, label, tool_call):
		task = _make_loop_task()
		try:
			_items, _n, aborted = _run(task, [_resp(tool_calls=[tool_call])])
		except Exception as e:  # noqa: BLE001 - the whole point is nothing escapes
			self.fail(f"[{label}] raised out of the loop: {type(e).__name__}: {e}")
		self.assertIsNone(
			aborted,
			f"[{label}] weird tool call aborted the session via the top-level catch-all: "
			f"{type(aborted).__name__ if aborted else None}: {aborted}")


def _make_weird_test(label, tool_call):
	def test(self):
		self._assert_survives(label, tool_call)
	test.__name__ = f"test_{label}"
	return test


for _label, _tool_call in WEIRD_TOOL_CALLS:
	setattr(TestWeirdToolCalls, f"test_{_label}", _make_weird_test(_label, _tool_call))


# ---------------------------------------------------------------------------
# 2. Non-tool-call weird responses (tailored expectations)
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAS_AI, 'ai addon required')
class TestWeirdContentResponses(unittest.TestCase):

	def test_single_empty_response_recovers(self):
		"""One empty response (no content, no tools) -> Warning, then continues."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content=None, tool_calls=[])])
		self.assertIsNone(aborted)
		self.assertGreaterEqual(n, 2)  # recovered and asked again

	def test_five_empty_responses_stop_cleanly(self):
		"""Five consecutive empties (the retry budget) stop with a clean Error, no abort."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content=None, tool_calls=[]) for _ in range(5)])
		self.assertIsNone(aborted)  # a deliberate Error, not the catch-all
		self.assertTrue(any(getattr(i, '_type', '') == 'error' for i in items))

	def test_empty_error_does_not_blame_tool_calling(self):
		"""The empty-response error must not (mis)claim the model can't call tools —
		most models can; empties are transient-provider / moderation / truncation."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content=None, tool_calls=[]) for _ in range(5)])
		err = next((i for i in items if getattr(i, '_type', '') == 'error'), None)
		self.assertIsNotNone(err)
		self.assertNotIn('support tool calling', getattr(err, 'message', ''))

	def test_content_filter_warns_once_and_waits_for_steer(self):
		"""content_filter is NOT retried or killed: warn ONCE, then wait for the user
		to steer (refine the request) in the same worker. With AutoBackend the wait
		returns None -> clean exit, no Error, no retry spam."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content=None, tool_calls=[], finish_reason="content_filter")])
		self.assertIsNone(aborted)
		filt = [getattr(i, 'message', '') for i in items
				if getattr(i, '_type', '') == 'warning' and 'content filter' in getattr(i, 'message', '')]
		self.assertEqual(len(filt), 1, filt)  # exactly one content-filter warning
		self.assertFalse([i for i in items if getattr(i, '_type', '') == 'error'])  # not killed

	def test_persistent_content_filter_never_errors(self):
		"""Repeated content_filter must never exhaust retries into an Error/kill — it
		warns once then waits for the user (exits cleanly under AutoBackend), so the
		task is resumable instead of dead."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content=None, tool_calls=[], finish_reason="content_filter")
										  for _ in range(5)])
		self.assertIsNone(aborted)
		self.assertFalse([i for i in items if getattr(i, '_type', '') == 'error'])

	def test_length_finish_reason_reports_truncation(self):
		"""An empty turn with finish_reason=length is reported as a truncation/output-cap
		issue, not a generic empty response."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content=None, tool_calls=[], finish_reason="length")])
		self.assertIsNone(aborted)
		self.assertGreaterEqual(n, 2)  # recovered and asked again
		warns = [getattr(i, 'message', '') for i in items if getattr(i, '_type', '') == 'warning']
		self.assertTrue(any('truncated' in w or 'length' in w for w in warns), warns)

	def test_missing_usage_does_not_crash(self):
		"""usage=None must not crash accounting."""
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content="hi", tool_calls=[], usage=None)])
		self.assertIsNone(aborted)
		self.assertEqual(task.context["ai_tokens"], 0)

	def test_huge_content_does_not_crash(self):
		task = _make_loop_task()
		items, n, aborted = _run(task, [_resp(content="A" * 500_000, tool_calls=[])])
		self.assertIsNone(aborted)


# ---------------------------------------------------------------------------
# 3. Fuzzer: random malformed arguments across every tool
# ---------------------------------------------------------------------------

_TOOL_NAMES = ["run_task", "run_workflow", "run_shell", "query_workspace", "follow_up", "add_finding", "stop"]


def _random_weird_arguments(rng):
	"""Produce a plausibly-broken `tool_call.arguments` string a model might emit."""
	kind = rng.choice([
		"valid_int", "valid_array", "valid_string", "unbalanced", "trailing_comma",
		"empty", "not_json", "stringified_nested", "wrong_types", "null_fields",
	])
	if kind == "valid_int":
		return str(rng.randint(0, 10_000))
	if kind == "valid_array":
		return json.dumps([rng.choice(["a", 1, None, True]) for _ in range(rng.randint(0, 4))])
	if kind == "valid_string":
		return json.dumps("".join(rng.choice("abc {}[]\"") for _ in range(rng.randint(0, 20))))
	if kind == "unbalanced":
		return '{"name": "x", "opts": {' + '"k": 1' * rng.randint(0, 2)
	if kind == "trailing_comma":
		return '{"name": "nmap", "targets": ["x"],}'
	if kind == "empty":
		return rng.choice(["", "   ", "{}"])
	if kind == "not_json":
		return rng.choice(["not json", "<html>", "```json\n{}\n```", "\x00\x01"])
	if kind == "stringified_nested":
		return json.dumps({"name": "nmap", "targets": '["a","b"]', "opts": '{"x":1}'})
	if kind == "wrong_types":
		return json.dumps({"name": rng.choice([1, None, [], {}]), "targets": rng.choice(["s", 5, {}]),
						   "opts": rng.choice([5, "str", []]), "query": rng.choice([[], "s", 9])})
	# null_fields
	return json.dumps({"name": None, "targets": None, "opts": None, "query": None, "command": None})


@unittest.skipUnless(HAS_AI, 'ai addon required')
class TestMalformedArgFuzzer(unittest.TestCase):
	"""Random malformed arguments across all tools must never abort the loop."""

	def test_fuzz_arguments_never_abort_loop(self):
		rng = random.Random(1337)  # deterministic: any failure reproduces
		failures = []
		for i in range(200):
			name = rng.choice(_TOOL_NAMES)
			raw = _random_weird_arguments(rng)
			task = _make_loop_task()
			tool_call = _tc(name, raw, call_id=f"f{i}")
			try:
				_items, _n, aborted = _run(task, [_resp(tool_calls=[tool_call])])
			except Exception as e:  # noqa: BLE001
				failures.append(f"#{i} {name} args={raw!r} -> RAISED {type(e).__name__}: {e}")
				continue
			if aborted is not None:
				failures.append(f"#{i} {name} args={raw!r} -> ABORTED ({type(aborted).__name__}: {aborted})")
		self.assertEqual(failures, [], f"{len(failures)} resilience failures:\n" + "\n".join(failures[:20]))


@unittest.skipUnless(HAS_AI, 'ai addon required')
class TestUserInputTimeoutPropagates(unittest.TestCase):
	"""A remote permission prompt that times out (UserInputTimeout raised inside
	check_guardrails) must NOT be swallowed as a fed-back 'Guardrail check failed'
	denial — that made the model retry into another prompt → another timeout, a loop
	that left the runner stuck RUNNING. It must propagate to the loop's outer handler,
	which exits the worker cleanly with the prompt left pending (one LLM call, no loop)."""

	def test_timeout_exits_clean_not_looped(self):
		from secator.ai.interactivity import UserInputTimeout

		def _timeout_guardrails(action, ctx):
			if False:  # make this a generator (matches `yield from check_guardrails`)
				yield
			raise UserInputTimeout("No answer for permission prompt after 600s")

		task = _make_loop_task()
		task.dangerous = False  # exercise the guardrail path
		with patch('secator.tasks.ai.check_guardrails', _timeout_guardrails):
			items, calls, aborted = _run(
				task, [_resp(tool_calls=[_tc('run_shell', '{"command": "nmap -sV x"}')])])

		texts = " ".join(
			str(getattr(i, 'content', '') or getattr(i, 'message', '') or '') for i in items)
		# Not turned into a denial fed back to the LLM
		self.assertNotIn("Guardrail check failed", texts)
		# Exited after the single turn instead of looping back into another LLM call
		self.assertEqual(calls, 1)

	def test_arg_error_still_fed_back_as_denial(self):
		"""Contrast: a ValueError (bad action args) is STILL turned into a denial and
		fed back so the model can retry with a valid target (loop continues)."""
		def _bad_args(action, ctx):
			if False:
				yield
			raise ValueError("'HOST:xyz' does not appear to be an IPv4 or IPv6 address")

		task = _make_loop_task()
		task.dangerous = False  # exercise the guardrail path
		with patch('secator.tasks.ai.check_guardrails', _bad_args):
			items, calls, aborted = _run(
				task, [_resp(tool_calls=[_tc('run_shell', '{"command": "nmap x"}')])])
		texts = " ".join(
			str(getattr(i, 'content', '') or getattr(i, 'message', '') or '') for i in items)
		self.assertIn("Guardrail check failed", texts)
		self.assertGreaterEqual(calls, 2)  # fed back -> model asked again


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestDetectModeEmptyPromptSetsTools(unittest.TestCase):
	"""Regression: an empty-prompt RESUME (respawn after the worker exited on a
	pending prompt) must still leave `tool_schemas` set. The empty-prompt branch of
	_detect_mode used to return early without building tools, so _run_loop then
	raised `AttributeError: 'ai' object has no attribute 'tool_schemas'`."""

	def test_empty_prompt_builds_tools_and_defaults_chat(self):
		task = ai.__new__(ai)
		task.prompt = ""      # empty (resume)
		task.mode = None      # not yet set
		built = []
		task._rebuild_prompt_and_tools = lambda: (built.append(True), setattr(task, 'tool_schemas', []))

		task._detect_mode()

		self.assertTrue(built, "_detect_mode must build tools on the empty-prompt path")
		self.assertEqual(task.mode, "chat")
		self.assertTrue(hasattr(task, "tool_schemas"))
