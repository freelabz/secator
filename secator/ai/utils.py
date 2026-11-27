# secator/ai/utils.py
"""Utility functions for AI task - LLM initialization, calling, and response parsing."""
import json
import logging
import os
import random
import re
from dataclasses import fields
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from secator.definitions import LLM_SPINNER_MESSAGES
from secator.config import CONFIG, mask_secret, mask_url
from secator.output_types import Warning, Error
from rich.markup import escape

from secator.rich import console, maybe_status
from secator.runners import Task
from secator.utils import format_token_count, to_datetime

# Module-level state for litellm initialization
_llm_initialized = False


SENSITIVE_ENV_PREFIXES = (
	"SECATOR_",
	"ANTHROPIC_", "OPENAI_", "GOOGLE_", "AZURE_", "AWS_", "GCP_",
	"GITHUB_TOKEN", "GITLAB_TOKEN", "SLACK_TOKEN", "DISCORD_TOKEN",
	"SECRET_", "TOKEN_", "API_KEY", "PRIVATE_KEY",
)


def _sanitized_env() -> dict:
	"""Return a copy of os.environ with sensitive variables removed.

	Passed as the `env` run_opt to the AI shell `command` runner so an AI-run
	`env`/`printenv` can't dump the LLM key + cloud creds into output that flows
	back to the LLM and is persisted to Mongo.
	"""
	# Case-insensitive: lowercase/mixed-case names (openai_api_key, database_password)
	# must be filtered too, so match against the upper-cased name.
	def _sensitive(name: str) -> bool:
		u = name.upper()
		return (any(u.startswith(p) for p in SENSITIVE_ENV_PREFIXES)
				or any(s in u for s in ("KEY", "SECRET", "TOKEN", "PASSWORD")))
	return {k: v for k, v in os.environ.items() if not _sensitive(k)}


# Files/paths that hold platform secrets (Mongo/Celery URLs, LLM keys). Reading any
# of these from an AI shell command is forbidden UNCONDITIONALLY — this deny lives
# outside the permission engine on purpose, so it still holds when dangerous=True
# nulls the engine and disables every other guardrail.
_SECRET_READ_MARKERS = ("/.secator/config.yml", "/.secator/config.yaml", "/.secator/.env")
_PROC_ENVIRON_RE = re.compile(r"/proc/\S*/environ")
# A connection URL carrying inline credentials: scheme://user:pass@host…
_CREDS_URL_RE = re.compile(r"[a-zA-Z][\w+.\-]*://[^\s:/@]+:[^\s@/]+@[^\s'\"]*")


def _denied_secret_read(command: str) -> Optional[str]:
	"""Return a denial reason if the command would read a secator secret source, else None.

	Blocks the two file sources (``~/.secator/config.yml`` / ``.env``) and the
	parent-process env-leak vector (``/proc/<pid>/environ`` bypasses _sanitized_env,
	which only cleans the child's own environment). Reads elsewhere (e.g. the run's
	report outputs under ~/.secator/reports/) are unaffected.
	"""
	c = command.lower()
	if any(m in c for m in _SECRET_READ_MARKERS):
		return "Reading secator config/.env files is forbidden — they contain platform secrets."
	if _PROC_ENVIRON_RE.search(c):
		return "Reading process environment via /proc is forbidden — it exposes platform secrets."
	return None


def loads_lenient(s: str):
	"""json.loads, tolerating trailing junk after a complete top-level {...}/[...].

	LLMs occasionally append an extra brace or prose after an otherwise-valid JSON
	object (observed: `{"_type":"vulnerability",...}}}` with a stray `}`). A strict
	json.loads rejects the whole thing; here, on failure, we re-parse just the first
	balanced top-level object/array. Raises the ORIGINAL JSONDecodeError if no such
	balanced prefix exists, so the caller's clear error message still fires.
	"""
	try:
		return json.loads(s)
	except json.JSONDecodeError as first:
		s2 = s.strip()
		if not s2 or s2[0] not in "{[":
			raise first
		open_ch = s2[0]
		close_ch = "}" if open_ch == "{" else "]"
		depth = 0
		in_str = False
		esc = False
		for i, ch in enumerate(s2):
			if in_str:
				if esc:
					esc = False
				elif ch == "\\":
					esc = True
				elif ch == '"':
					in_str = False
				continue
			if ch == '"':
				in_str = True
			elif ch == open_ch:
				depth += 1
			elif ch == close_ch:
				depth -= 1
				if depth == 0:
					return json.loads(s2[:i + 1])  # may raise; the balanced prefix is still invalid
		raise first


def _secret_values() -> set:
	"""Concrete secret strings that must never reach the LLM/transcript.

	Values of clearly-secret env vars (LLM/cloud keys, tokens, passwords) plus any
	env value that is a credentialed connection URL (Mongo/AMQP/redis). Non-secret
	SECATOR_* values (ports, frequencies) are deliberately excluded so scrubbing
	can't corrupt legitimate output.
	"""
	vals = set()
	for k, v in os.environ.items():
		if not v or len(v) < 8:
			continue
		u = k.upper()
		looks_secret = any(s in u for s in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE"))
		is_conn = "://" in v and re.search(r"://[^\s:/@]+:[^\s@/]+@", v) is not None
		if looks_secret or is_conn:
			vals.add(v)
	return vals


def _scrub_secrets(text: str) -> str:
	"""Redact platform secrets from shell output before it is persisted/shown.

	Defense-in-depth for every leak vector _sanitized_env can't cover (config files,
	/proc, process args): redacts exact secret values verbatim, then redacts any
	remaining credentialed connection URL whole (scheme through host/path).
	"""
	if not text:
		return text
	for v in _secret_values():
		text = text.replace(v, "[REDACTED]")
	text = _CREDS_URL_RE.sub("[REDACTED]", text)
	return text


def _build_action_display(action: Dict) -> str:
	"""Build a display string for the action being checked.

	Returns a concise description of the command/task/workflow for prompt context.
	"""
	action_type = action.get("action", "")
	if action_type == "shell":
		return action.get("command", "")
	elif action_type in ("task", "workflow"):
		name = action.get("name", "")
		targets = action.get("targets", [])
		opts = action.get("opts", {})
		parts = [f"{action_type}: {name}"]
		if targets:
			parts.append(f"targets={targets}")
		if opts:
			parts.append(f"opts={opts}")
		return " ".join(parts)
	return ""


def _is_approved(response) -> bool:
	# Explicit allow-list: only a normalized "allow" answer approves. None, "deny",
	# or any unexpected token denies (fail closed) — so a new backend or a refactored
	# answer vocabulary can't silently approve via a "not deny" gap.
	return bool(response) and response.get("answer") == "allow"


def _truncate(text: str, max_chars: int) -> str:
	"""Cap ``text`` to ~``max_chars``, keeping head + tail so both the start and the
	final lines survive, with a clear marker for the dropped middle. Short text is
	returned unchanged (no marker)."""
	if len(text) <= max_chars:
		return text
	dropped = len(text) - max_chars
	half = max_chars // 2
	return f"{text[:half]}\n…(truncated {dropped} chars)…\n{text[-(max_chars - half):]}"


def _format_action_error(e: Exception, max_chars: int = 400) -> str:
	"""Build a concise, LLM-facing error string for a failed action dispatch.

	Combines the exception type + message with the last few traceback frames (that's
	where the actual failure is) so the model can see *where* it failed, then
	truncates so a deep traceback can't blow up the next prompt's token budget.
	"""
	import traceback

	errtype = type(e).__name__
	msg = str(e)
	head = f"{errtype}: {msg}" if msg else errtype

	tb_lines = traceback.format_exc().strip().splitlines()
	tb_tail = "\n".join(tb_lines[-6:]) if tb_lines else ""

	detail = f"{head}\n{tb_tail}" if tb_tail else head
	detail = _truncate(detail, max_chars)
	return (
		f"Action failed with error: {detail}\n"
		"Fix the issue and try again."
	)


def _is_heavy_runner(runner_type: str, name: str, opts: dict = None, targets: list = None) -> bool:
	"""Whether a sub-runner must be dispatched to its own queue instead of running sync
	in-process inside the ai worker.

	Workflows/scans fan out across multiple pools, so they are always dispatched. An AI
	subagent stays in-process. A task is dispatched when it is:

	- heavy: its queue profile (dynamic profile or ``tasks.overrides.<task>.profile``) is one
	  of ``addons.ai.dispatch_profiles``;
	- wide: it would be split into chunks for these targets, or it has more than
	  ``addons.ai.inline_max_targets`` targets. In-process work then never chunks, and the
	  chunks run in parallel on the worker pools.
	"""
	if runner_type != 'task':
		return True
	from secator.ai.tools._runner import resolves_to_ai_task  # lazy: _runner imports this module
	if resolves_to_ai_task(name):  # `ai` and `ai/<suffix>`
		return False
	try:
		cls = Task.get_task_class(name)
	except Exception:
		return False
	targets = list(dict.fromkeys(targets or []))
	if len(targets) > CONFIG.addons.ai.inline_max_targets:
		return True
	# Inputs the child pulls from earlier results at build time (a `targets_` extractor, or the
	# targets tagged with a `parent_scope`) are unknown here and can make it wide: dispatch.
	opts = opts or {}
	if opts.get('parent_scope') or any(str(k).endswith('_') and str(k).rstrip('_') == 'targets' for k in opts):
		return True
	# Same rule as the task's own needs_chunking(), evaluated before the child is built. In a
	# worker the chunk check runs with the async rule (input_chunk_size); the sync rule is checked
	# too so the decision does not depend on where that check runs (at worst: one more dispatch).
	would_chunk = getattr(cls, 'would_chunk', None)
	if would_chunk and (would_chunk(targets, True, opts) or would_chunk(targets, False, opts)):
		return True
	from secator.runners._helpers import resolve_task_queue
	try:
		profile = resolve_task_queue(cls, opts)
	except Exception:
		return True  # can't resolve — be conservative and dispatch
	return profile in set(CONFIG.addons.ai.dispatch_profiles or [])


# Framework control/security keys the LLM must never set on a spawned sub-runner
# (esp. `dangerous`, which skips the permission engine). Task/workflow scan opts
# (nmap ports, httpx rate_limit, ...) are not control keys and pass through.
_FORBIDDEN_CHILD_OPT_KEYS = frozenset({
	"dangerous",
	"interactive",
	"hooks",
	"sync",
	"subagent",
	"tty",
	"dry_run",
	"exporters",
	"enable_reports",
	# SECURITY (ISOLATION): child can't lower isolation — `isolated` is force-inherited, stripped here.
	"isolated",
})

# Cap a spawned subagent's iteration budget so it can't be told to loop unbounded.
_MAX_CHILD_ITERATIONS = 25

# ai_types that mean a subagent persisted something (single source for the handback detector).
_PERSIST_AI_TYPES = frozenset({
	"add_finding", "mark_vuln_exploited", "mark_vuln_false_positive", "mark_vuln_exploit_failed"})


def _sanitize_child_opts(opts: Any) -> Dict:
	"""Drop LLM-settable control/security keys from sub-runner opts; clamp max_iterations."""
	if not isinstance(opts, dict):
		return {}
	clean = {}
	for key, value in opts.items():
		k = str(key)
		if k in _FORBIDDEN_CHILD_OPT_KEYS or k.startswith("print_"):
			continue
		clean[key] = value
	# Clamp the AI-subagent iteration budget (bool is an int subclass — drop it).
	mi = clean.get("max_iterations")
	if isinstance(mi, bool):
		clean.pop("max_iterations", None)
	elif isinstance(mi, (int, float)):
		clean["max_iterations"] = max(1, min(int(mi), _MAX_CHILD_ITERATIONS))
	elif mi is not None:
		clean.pop("max_iterations", None)
	return clean


def build_subagent_prompt(objective: str, targets: list, evidence: str) -> str:
	"""Wrap the LLM-supplied subagent objective in a structured prompt.

	The `objective` is used verbatim (the parent LLM's intent). `targets` scopes
	the work; `evidence` (auto-gathered, may be empty) is prior findings the
	subagent should NOT re-discover.
	"""
	targets_str = ", ".join(str(t) for t in targets) if targets else "(inherit parent scope)"
	evidence_block = evidence.strip() if evidence.strip() else "(none — no prior findings for this scope)"
	return (
		f"## Objective\n{objective.strip() or '(no explicit objective given)'}\n\n"
		f"## Scope\nWork ONLY within these target(s): {targets_str}\n\n"
		f"## Already known (do not re-run tools that would re-discover these)\n{evidence_block}\n\n"
		f"## Expected output\n"
		f"1. Do the work needed to meet the objective, within scope.\n"
		f"2. PERSIST your result — it's REQUIRED and is the ONLY output that survives (your prose "
		f"is NOT saved and the parent CANNOT read your transcript). On an EXISTING vulnerability "
		f"(`_uuid` from query_workspace), call `mark_vuln_exploited` with that `_uuid` "
		f"(working PoC), `mark_vuln_false_positive` (disproved), or `mark_vuln_exploit_failed` "
		f"(exploit attempt failed but the vuln may still be real). For a NEW finding, "
		f"call `add_finding`. You MUST persist before finishing if you confirmed OR disproved "
		f"anything.\n"
		f"3. Finish with a 2-4 line HANDBACK: what you did, the verdict "
		f"(confirmed / false-positive / inconclusive), and the `_uuid`(s) you persisted."
	)


def _union_live_results(persisted: List[Dict], live_results: List[Dict], query_filter: Dict, limit: int) -> List[Dict]:
	"""Union backend results with this run's in-memory findings (local driver only).

	The live findings are filtered by the SAME query via an in-memory json backend,
	then merged into the backend (disk) results and deduped by ``_uuid`` (backend wins),
	respecting ``limit``. Makes query_workspace the single source of truth under the
	local driver, whose JSON exporter only writes to disk at end-of-run.
	"""
	from secator.query._base import is_internal_doc
	# never surface internal ai docs (the placeholder map) to the model, whatever the query
	persisted = [r for r in persisted if not is_internal_doc(r)]
	if not live_results:
		return persisted
	# Filter this run's in-memory findings by the SAME query in-process. The JsonBackend
	# no longer reads an in-memory `results` context (it streams from disk), so we match
	# each live dict directly with the store's own matcher, then merge into the disk-backed
	# results and dedupe by ``_uuid`` (backend wins), respecting ``limit``.
	from secator.query.json import match_query
	seen = {r.get("_uuid") for r in persisted if r.get("_uuid")}
	for r in live_results:
		if is_internal_doc(r) or not match_query(r, query_filter):
			continue
		u = r.get("_uuid")
		if u and u in seen:
			continue
		persisted.append(r)
		if u:
			seen.add(u)
	return persisted[:limit] if limit else persisted


def _resolve_field_type(f) -> Optional[type]:
	"""Resolve a dataclass field's declared type to a concrete builtin type.

	Mirrors ``OutputType.validate_fields``: ``f.type`` may be an actual type
	(``bool``) or — under ``from __future__ import annotations`` — a string
	annotation (``'bool'``). Returns the concrete type (``bool``/``int``/
	``float``/``list``/``dict``/``str``) or ``None`` if it can't be resolved.
	"""
	t = f.type
	# Actual type, e.g. bool / int / float / str
	if isinstance(t, type):
		return t
	# Typing generic, e.g. List[str] -> list
	origin = getattr(t, '__origin__', None)
	if origin is not None:
		return origin
	# String annotation, e.g. 'bool', 'int', "List[str]"
	if isinstance(t, str):
		name = t.split('[', 1)[0].strip().lower()
		return {
			'bool': bool, 'int': int, 'float': float,
			'str': str, 'list': list, 'dict': dict, 'datetime': datetime,
		}.get(name)
	return None


def _coerce_finding_fields(cls, data: Dict) -> Dict:
	"""Coerce AI-provided scalar values to a finding class's declared field types.

	LLMs frequently emit wrong-typed scalars (a ``bool`` field as the string
	``"true"``, an ``int`` as ``"3"``). This fixes *obvious* type mismatches
	before validation so the finding isn't rejected for model type sloppiness.

	Only coerces when safe; unknown keys, already-correct values, and
	unparseable values are left untouched (validation will still surface a real
	error rather than silently dropping data).
	"""
	field_types = {f.name: _resolve_field_type(f) for f in fields(cls)}
	for key, value in list(data.items()):
		if key.startswith('_'):
			continue
		expected = field_types.get(key)
		if expected is None or value is None:
			continue
		# A scalar `str` field handed list-shaped data: the model packs multiple values into a
		# single field (e.g. `matched_at` as '["http://a","http://b"]' or a real list). A str value
		# already "matches" str and would slip past the type check below and get stored as an ugly
		# literal; a real list would be rejected by validate_fields. Unwrap to the first element so
		# it lands as a clean scalar. ponytail: first element is the representative location; extra
		# ones are dropped (a scalar field holds one). Mirrors the list-field coercion below.
		if expected is str:
			parsed = value
			if isinstance(value, str):
				s = value.strip()
				if s.startswith('[') and s.endswith(']'):
					try:
						loaded = json.loads(s)
						if isinstance(loaded, list):
							parsed = loaded
					except (json.JSONDecodeError, TypeError):
						parsed = value
			if isinstance(parsed, list):
				if not parsed:
					data[key] = ''
				elif isinstance(parsed[0], str):
					data[key] = parsed[0]
				# else: a non-string element (None, dict, ...) — leave the value unchanged so
				# validate_fields rejects the malformed type instead of storing "None"/a dict repr.
			continue
		# datetime fields: the model can only send JSON, so accept ISO 8601 strings, epoch numbers
		# and Mongo extended JSON ({'$date': ...}) and coerce to an aware UTC datetime. Unparseable
		# values are left as-is so validate_fields rejects them with the expected format.
		if expected is datetime:
			parsed = to_datetime(value)
			if parsed is not None:
				data[key] = parsed
			continue
		# Already the right type (note: bool is a subclass of int, so guard it).
		if isinstance(value, expected) and not (expected is int and isinstance(value, bool)):
			continue

		if expected is bool:
			if isinstance(value, bool):
				continue
			if isinstance(value, int):
				data[key] = bool(value)
			elif isinstance(value, str):
				s = value.strip().lower()
				if s in ('true', '1', 'yes', 'on'):
					data[key] = True
				elif s in ('false', '0', 'no', 'off', ''):
					data[key] = False
		elif expected is int:
			# Avoid coercing real bools into ints.
			if isinstance(value, bool):
				continue
			if isinstance(value, float):
				if value.is_integer():
					data[key] = int(value)
			elif isinstance(value, str):
				try:
					data[key] = int(value)
				except ValueError:
					try:
						f_val = float(value)
						if f_val.is_integer():
							data[key] = int(f_val)
					except ValueError:
						pass
		elif expected is float:
			if isinstance(value, bool):
				continue
			if isinstance(value, int):
				data[key] = float(value)
			elif isinstance(value, str):
				try:
					data[key] = float(value)
				except ValueError:
					pass
		elif expected is list:
			if isinstance(value, str):
				s = value.strip()
				if s.startswith('['):
					try:
						parsed = json.loads(s)
						if isinstance(parsed, list):
							data[key] = parsed
					except (json.JSONDecodeError, TypeError):
						pass
		# str fields: leave as-is (don't stringify); unknown types: leave untouched.
	return data


def _get_action_label(action: Dict) -> str:
	"""Get a display label for an action."""
	act_type = action.get("action", "unknown")
	if act_type in ("task", "workflow"):
		name = action.get("name", "?")
		opts = action.get("opts", {})
		# Defensive: a model may stringify `opts` (coerced at the tool-call boundary,
		# but a malformed value can survive as a str) — never crash a display label.
		session_name = opts.get("session_name", "") if isinstance(opts, dict) else ""
		if session_name:
			return session_name
		targets = action.get("targets", [])
		target_str = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
		return f"{name} on {target_str}"
	elif act_type == "shell":
		cmd = action.get("command", "")[:40]
		return f"shell: {cmd}"
	return act_type


def _decrypt_dict(d: Dict, encryptor: Any) -> Dict:
	"""Recursively decrypt all string values in a dict.

	Args:
		d: Dictionary to decrypt
		encryptor: SensitiveDataEncryptor instance

	Returns:
		Decrypted dictionary
	"""
	# Backstop: callers should pass a dict, but a non-dict (e.g. an LLM that
	# stringified an object arg) must not raise `.items()` here — return it
	# unchanged rather than crash the whole action.
	if not isinstance(d, dict):
		return d
	result = {}
	for k, v in d.items():
		if isinstance(v, str):
			result[k] = encryptor.decrypt(v)
		elif isinstance(v, dict):
			result[k] = _decrypt_dict(v, encryptor)
		elif isinstance(v, list):
			result[k] = [
				encryptor.decrypt(i) if isinstance(i, str)
				else _decrypt_dict(i, encryptor) if isinstance(i, dict)
				else i
				for i in v
			]
		else:
			result[k] = v
	return result


def _tool_call_fields(tc) -> Tuple[str, str]:
	"""Extract (name, arguments) from a tool_call, handling both the dict shape
	(litellm/OpenAI JSON) and the SDK object shape (attribute access)."""
	fn = tc.get("function", {}) if isinstance(tc, dict) else getattr(tc, "function", None)
	if isinstance(fn, dict):
		return fn.get("name", ""), fn.get("arguments", "")
	if fn is not None:
		return getattr(fn, "name", ""), getattr(fn, "arguments", "")
	return "", ""


def _strip_leading_orphan_tools(messages: List[Dict]) -> int:
	"""Drop leading 'tool' (tool_result) messages with no preceding tool_use.

	Truncation/compaction drops the OLDEST messages with no tool-pairing
	awareness, so the kept window can START with a tool_result whose
	assistant(tool_calls) parent was dropped. Anthropic/OpenAI reject such a
	leading orphan tool_result ("tool_result without matching tool_use").
	System messages are preserved; we scan past them and drop the run of
	leading 'tool' messages that follows. Mutates `messages` in place.

	Args:
		messages: List of message dicts in litellm/OpenAI format.

	Returns:
		Number of leading orphan tool messages removed.
	"""
	i = 0
	while i < len(messages) and messages[i].get("role") == "system":
		i += 1
	removed = 0
	while i < len(messages) and messages[i].get("role") == "tool":
		messages.pop(i)
		removed += 1
	return removed


def _strip_orphan_tool_blocks(messages: List[Dict]) -> int:
	"""Drop any run of 'tool' messages not rooted at an assistant(tool_calls) parent.

	Generalises ``_strip_leading_orphan_tools``: a tool-result block is valid only when the
	message immediately before it is an ``assistant`` carrying ``tool_calls``. Trim/compaction
	can drop that parent while a ``user`` (or other) message survives before the orphaned
	tool-block — leaving a ``tool`` message after a ``user``, which providers reject with
	"Unexpected role 'tool' after role 'user'" (#1465). Covers the leading-orphan case too
	(window starts with a tool whose parent was dropped). Mutates in place; returns count removed.
	"""
	removed = 0
	i = 0
	while i < len(messages):
		if messages[i].get("role") != "tool":
			i += 1
			continue
		prev = messages[i - 1] if i > 0 else None
		rooted = bool(prev and prev.get("role") == "assistant" and prev.get("tool_calls"))
		if rooted:
			# Within the block, also drop a result whose id is not one of the parent's
			# calls ("No tool call found for function call output with call_id ...").
			ids = {tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None) for tc in prev["tool_calls"]}
			while i < len(messages) and messages[i].get("role") == "tool":
				if messages[i].get("tool_call_id") in ids:
					i += 1
				else:
					messages.pop(i)
					removed += 1
			continue
		while i < len(messages) and messages[i].get("role") == "tool":
			messages.pop(i)
			removed += 1
	return removed


def _dedupe_tool_results(messages: List[Dict]) -> int:
	"""Drop duplicate tool_result messages sharing a tool_call_id.

	Anthropic (and OpenRouter's providers) fold consecutive 'tool' messages into a
	single user turn and reject more than one tool_result per tool_use id
	("each tool_use must have a single result. Found multiple tool_result blocks
	with id X") — a NON-retryable 400. Duplicates arise when batch results are
	grouped out of order (itertools.groupby only groups *consecutive* keys), or
	when history trim/compaction restructures the window. Within each run of
	consecutive 'tool' messages, keep the first result for each id and drop the
	rest (in place). Returns the number removed.
	"""
	removed = 0
	i = 0
	while i < len(messages):
		if messages[i].get("role") != "tool":
			i += 1
			continue
		seen = set()
		j = i
		while j < len(messages) and messages[j].get("role") == "tool":
			tc_id = messages[j].get("tool_call_id")
			if tc_id is not None and tc_id in seen:
				del messages[j]
				removed += 1
				continue  # a message shifted into j; re-check without advancing
			if tc_id is not None:
				seen.add(tc_id)
			j += 1
		i = j
	return removed


# Tool result recorded for a call that ran but produced nothing to report (e.g. `stop`, which
# ends the turn, or a tool whose only output is a display item).
TOOL_ACK_RESULT = '{"status":"acknowledged"}'

# Placeholder for a tool call that has NO recorded result. Every call the `ai` task dispatches
# gets a result in history (see `_ack_resultless_calls` in the `ai` task), so a call without one
# was interrupted before it returned: the run ended while waiting on a permission answer, or the
# worker stopped mid-turn, and the turn is restored later. Never answer it with TOOL_ACK_RESULT:
# the model would read "ran, no output" for a call that never executed.
TOOL_NOT_RUN_RESULT = json.dumps({
	"status": "not_run",
	"error": (
		"No result was recorded for this call: the run was interrupted before it returned "
		"(e.g. it ended while waiting for a permission answer, or stopped mid-turn). It may "
		"not have run, or may have run without its result reaching you. This is not an error "
		"from the command itself, nor from running calls in parallel. Check for its effects "
		"before re-issuing it (for a task, workflow or scan, query the workspace for its "
		"findings)."),
}, separators=(',', ':'))

# Tools whose calls never get a tool_result by design: `stop` ends the turn and the user's
# answer follows it directly (`follow_up` is its former name, still found in older
# transcripts). A missing result for these is expected, not an interruption.
_RESULTLESS_TOOLS = frozenset({"stop", "follow_up"})


def _repair_orphan_tool_uses(messages: List[Dict]) -> int:
	"""Repair orphan tool_use/tool_result pairing for Anthropic/OpenAI.

	Two defects are fixed (both mutate `messages` in place):
	- LEADING orphan tool_results: a kept window starting with a tool_result
	  whose assistant(tool_calls) parent was trimmed away (see
	  `_strip_leading_orphan_tools`).
	- FORWARD orphan tool_uses: an assistant tool_use block not immediately
	  followed by a matching tool_result. A `stop` call gets an acknowledged
	  result; any other call gets TOOL_NOT_RUN_RESULT, since a dispatched call
	  always has a recorded result and a missing one means it was interrupted.

	Args:
		messages: List of message dicts in litellm/OpenAI format.

	Returns:
		Number of messages removed or synthetic tool_results inserted.
	"""
	# Orphan tool_results (leading, or stranded after a user when the assistant(tool_calls)
	# parent was trimmed) have no matching tool_use in this window — drop them so providers
	# don't reject "tool_result without matching tool_use" / "tool after role user".
	repaired = _strip_orphan_tool_blocks(messages)
	# Duplicate tool_results for one id are rejected as a non-retryable 400 — drop
	# extras so the request is valid (and, when hit as a 400, so the retry repairs it).
	repaired += _dedupe_tool_results(messages)
	inserted = 0
	i = 0
	while i < len(messages):
		msg = messages[i]
		tool_calls = msg.get("tool_calls") if msg.get("role") == "assistant" else None
		if not tool_calls:
			i += 1
			continue

		# Scan the contiguous 'tool' messages that follow; record satisfied ids.
		j = i + 1
		satisfied = set()
		while j < len(messages) and messages[j].get("role") == "tool":
			tc_id = messages[j].get("tool_call_id")
			if tc_id:
				satisfied.add(tc_id)
			j += 1

		# Synthesize missing tool_results, inserting them just before the next
		# non-tool message so they stay within the tool-response block.
		to_insert = []
		for tc in tool_calls:
			tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)
			if not tc_id or tc_id in satisfied:
				continue
			name, _ = _tool_call_fields(tc)
			to_insert.append({
				"role": "tool",
				"tool_call_id": tc_id,
				"name": name,
				"content": TOOL_ACK_RESULT if name in _RESULTLESS_TOOLS else TOOL_NOT_RUN_RESULT,
			})

		if to_insert:
			messages[j:j] = to_insert
			inserted += len(to_insert)
			j += len(to_insert)

		i = j
	return repaired + inserted


def init_llm(api_key: Optional[str] = None):
	"""Initialize litellm once (singleton pattern to avoid callback accumulation)."""
	global _llm_initialized

	import litellm

	# Set the key of THIS call, clearing any earlier one: litellm.api_key is process-wide, so a
	# stale key would otherwise be sent to whatever provider a later key-less call targets.
	litellm.api_key = api_key or None

	if _llm_initialized:
		return

	from litellm.integrations.custom_logger import CustomLogger

	# Suppress litellm's own debug logs unless 'litellm.debug' is explicitly set
	if "litellm.debug" not in CONFIG.debug:
		litellm.suppress_debug_info = True
		litellm.set_verbose = False
		litellm.json_logs = True
		logging.getLogger("LiteLLM").setLevel(logging.WARNING)
		logging.getLogger("litellm").setLevel(logging.WARNING)
		logging.getLogger("httpx").setLevel(logging.WARNING)

	class LLMCallbackHandler(CustomLogger):
		"""Custom handler for logging LLM calls."""
		_last_message_count = 0

		def log_pre_api_call(self, model, messages, kwargs):
			if "litellm" not in CONFIG.debug:
				return
			from secator.rich import CustomMarkdown as Markdown
			from rich.panel import Panel
			from rich.text import Text
			from rich.console import Group
			MAX_LEN = 2000
			role_styles = {"system": "blue", "user": "green", "assistant": "red", "tool": "yellow"}
			message_count = len(messages)
			# Only update counter when conversation is growing (same conversation)
			# A smaller message list means a side call (e.g. detect_mode) — show all, don't update
			is_side_call = message_count <= self._last_message_count
			prev_count = 0 if is_side_call else self._last_message_count
			if not is_side_call:
				self._last_message_count = message_count
			panels = []
			if prev_count > 0:
				panels.append(Text(f"... {prev_count} previous message(s) hidden ...", style="dim"))
			for count, msg in enumerate(messages, 1):
				if count <= prev_count:
					continue
				role = msg.get("role", "unknown").upper()
				content = msg.get("content", "").strip()
				style = role_styles.get(msg.get("role", ""), "white")
				if "litellm.raw" not in CONFIG.debug:
					if len(content) > MAX_LEN:
						content = content[:MAX_LEN] + f"\n\n... ({len(content) - MAX_LEN} chars truncated)"
				# For assistant messages with tool_calls, show the tool calls
				if msg.get("role") == "assistant" and msg.get("tool_calls"):
					parts = [content] if content else []
					for tc in msg["tool_calls"]:
						fn = tc.get("function", {})
						parts.append(f"**tool_call**: `{fn.get('name', '')}({fn.get('arguments', '')})`")
					renderable = Markdown("\n\n".join(parts))
				elif msg.get("role") == "assistant":
					renderable = Markdown(content)
				else:
					renderable = Text(content)

				# For tool results, pretty-print the JSON content
				title_extra = ""
				if msg.get("role") == "tool":
					tool_name = msg.get("name", msg.get("tool_call_id", ""))
					title_extra = f" [dim]{tool_name}[/]"
					try:
						from rich.pretty import Pretty
						data = json.loads(content)
						renderable = Pretty(data)
					except (ValueError, TypeError):
						pass

				panels.append(Panel(
					renderable,
					title=f"[bold {style}]{role}[/]{title_extra} [dim]({count}/{message_count})[/]",
					border_style=style
				))
			console.print(Panel(
				Group(*panels),
				title=f"[bold white]LLM REQUEST[/] [dim]({message_count} messages)[/]",
				border_style="white"
			))

		def log_success_event(self, kwargs, response_obj, start_time, end_time):
			if "litellm" not in CONFIG.debug or not response_obj.choices:
				return
			from secator.rich import CustomMarkdown as Markdown
			from rich.panel import Panel
			message = response_obj.choices[0].message
			content = message.content or ""
			tool_calls = getattr(message, 'tool_calls', None) or []
			parts = []
			if content:
				parts.append(content)
			for tc in tool_calls:
				parts.append(f"**tool_call**: `{tc.function.name}({tc.function.arguments})`")
			text = "\n\n".join(parts) if parts else "(empty response)"
			if "litellm.raw" not in CONFIG.debug:
				MAX_LEN = 2000
				if len(text) > MAX_LEN:
					text = text[:MAX_LEN] + f"\n\n... ({len(text) - MAX_LEN} chars truncated)"
			console.print(Panel(
				Markdown(text),
				title="[bold red]LLM RESPONSE[/]",
				border_style="red"
			))

	litellm.callbacks = [LLMCallbackHandler()]
	_llm_initialized = True


def _estimate_usage(model: str, messages: List[Dict], content: str, tool_calls) -> Dict:
	"""Estimate tokens when the provider omits `usage`, so calls are never unmetered.

	Uses litellm's own token counter for the model in use — prompt tokens from the
	request messages, completion tokens from the response text (+ any tool-call
	name/arguments). Returns the same shape as the real-usage dict (cost unknown).
	"""
	import litellm

	def _count(**kw):
		try:
			return litellm.token_counter(model=model, **kw) or 0
		except Exception:
			return 0

	prompt_tokens = _count(messages=messages)
	completion_text = content or ""
	for tc in tool_calls or []:
		name, args = _tool_call_fields(tc)
		completion_text += f" {name} {args}"
	completion_tokens = _count(text=completion_text)
	return {
		"tokens": prompt_tokens + completion_tokens,
		"prompt_tokens": prompt_tokens,
		"completion_tokens": completion_tokens,
		"cost": None,
	}


class OAuth2TokenCache:
	"""In-memory OAuth2 client-credentials access token for the configured LLM endpoint.

	The token is fetched from ``addons.ai.oauth2_endpoint`` and reused until shortly before
	its ``expires_in``; ``get(force=True)`` refetches it (e.g. after a 401). It is never
	logged or persisted.
	"""

	REFRESH_MARGIN = 30  # seconds before expiry to refetch

	def __init__(self):
		import threading
		self._lock = threading.Lock()
		self._key = None
		self._token = None
		self._expires_at = 0.0

	def get(self, cfg=None, force=False):
		"""The access token for ``cfg`` (a :func:`resolve_ai_profile` result; default: the active profile)."""
		import time
		cfg = cfg or resolve_ai_profile()
		key = (cfg['oauth2_endpoint'], cfg['oauth2_client_id'], cfg['oauth2_client_secret'], cfg['oauth2_scope'])
		with self._lock:
			if force or key != self._key or time.monotonic() >= self._expires_at:
				self._token, ttl = self._fetch(*key)
				self._key = key
				self._expires_at = time.monotonic() + max(ttl - self.REFRESH_MARGIN, ttl / 2)
			return self._token

	@staticmethod
	def _fetch(endpoint, client_id, client_secret, scope):
		"""POST a client_credentials grant (RFC 6749 4.4, HTTP Basic client auth)."""
		import math
		import requests
		from urllib.parse import quote_plus
		_, err = _normalize_api_base(endpoint)
		if err:
			raise ValueError('addons.ai.oauth2_endpoint must be https:// (http:// only for a bare localhost host).')
		data = {'grant_type': 'client_credentials'}
		if scope:
			data['scope'] = scope
		resp = requests.post(
			# RFC 6749 2.3.1: form-encode both parts before HTTP Basic.
			endpoint, data=data, auth=(quote_plus(client_id, safe=''), quote_plus(client_secret, safe='')),
			timeout=15, allow_redirects=False, verify=_ssl_verify())
		if resp.status_code != 200:
			raise RuntimeError(f'OAuth2 token request failed (HTTP {resp.status_code}).')
		try:
			body = resp.json()
			token = body['access_token']
			ttl = 300.0 if body.get('expires_in') is None else float(body['expires_in'])
		except (ValueError, KeyError, TypeError):
			token, ttl = None, 0
		# An empty token would make litellm fall back to another configured key for this base.
		if not token or not isinstance(token, str) or not math.isfinite(ttl) or ttl <= 0:
			raise RuntimeError('OAuth2 token response has no valid access_token.')
		return token, ttl


# Process-wide so every call (agent loop, subagents, compaction) shares one token; keeping it on the
# runner would put the token into runner state and subagent opts.
_oauth2_tokens = OAuth2TokenCache()


def default_oauth2_token_url(api_base):
	"""Suggested OAuth2 token URL for an API base: its origin + ``/oauth2/token`` ('' without a base).

	Only a prefilled suggestion for setup: never used as a runtime fallback, so the client
	secret is only ever sent to a token URL the user set explicitly.

	``https://company.com/v1`` -> ``https://company.com/oauth2/token``.
	"""
	from urllib.parse import urlsplit
	parts = urlsplit((api_base or '').strip())
	if not parts.scheme or not parts.netloc:
		return ''
	host = parts.netloc.rpartition('@')[2]  # never carry userinfo into the token URL
	return f'{parts.scheme}://{host}/oauth2/token'


# The fields of an AI profile (addons.ai.profiles.<name>), and the addons.ai field each one falls back to.
_PROFILE_FIELDS = {
	'model': 'default_model', 'intent_model': 'intent_model', 'api_base': 'api_base', 'api_key': 'api_key',
	'oauth2_endpoint': 'oauth2_endpoint', 'oauth2_client_id': 'oauth2_client_id',
	'oauth2_client_secret': 'oauth2_client_secret', 'oauth2_scope': 'oauth2_scope',
}
_ENDPOINT_FIELDS = ('api_key', 'oauth2_endpoint', 'oauth2_client_id', 'oauth2_client_secret', 'oauth2_scope')
DEFAULT_PROFILE = 'default'  # the addons.ai fields themselves


def resolve_ai_profile(name=None):
	"""The model settings of AI profile ``name`` (``None`` = the active ``addons.ai.profile``).

	``default`` (or ``''``) is the addons.ai fields. A profile field left unset falls back to the
	addons.ai one, except with another ``api_base`` or ``oauth2_endpoint``: there the credentials
	stay empty and the intent model is the profile's model, so they never go to that other endpoint.
	(Like ``--model``, a profile that only changes the model reuses the addons.ai key.)

	Returns:
		dict: ``name`` plus the ``_PROFILE_FIELDS`` keys. Holds secrets: never log or persist it.

	Raises:
		ValueError: no profile has that name.
	"""
	cfg = CONFIG.addons.ai
	name = (cfg.profile if name is None else name) or DEFAULT_PROFILE
	merged = {field: cfg[key] or '' for field, key in _PROFILE_FIELDS.items()}
	if name == DEFAULT_PROFILE:
		return {'name': name, **merged}
	profiles = cfg.profiles or {}
	if name not in profiles:
		raise ValueError(f'Unknown AI profile "{name}". Known: {", ".join([DEFAULT_PROFILE, *profiles])}.')
	own = {k: v for k, v in (profiles[name] or {}).items() if k in _PROFILE_FIELDS and v is not None}
	if any(k in own and own[k].rstrip('/') != merged[k].rstrip('/') for k in ('api_base', 'oauth2_endpoint')):
		merged.update({field: '' for field in _ENDPOINT_FIELDS}, intent_model=own.get('model', merged['model']))
	return {'name': name, **merged, **own}


def _uses_oauth2(api_base, api_key, cfg):
	"""Whether this call gets the OAuth2 token: only with no explicit key, on the profile's base."""
	base = (cfg['api_base'] or '').rstrip('/')
	return bool(cfg['oauth2_endpoint'] and base and not api_key and (api_base or '').rstrip('/') == base)


def call_llm(
	messages: List[Dict],
	model: str,
	temperature: float = 0.7,
	api_base: Optional[str] = None,
	api_key: Optional[str] = None,
	tools: Optional[List[Dict]] = None,
	profile: Optional[str] = None,
) -> Dict:
	"""Call litellm completion and return response with usage.

	``profile`` (an addons.ai.profiles name, ``None`` = the active one) gives the OAuth2 settings used
	when no ``api_key`` is passed.
	"""
	import time
	import litellm

	max_retries = 3

	# Initialize litellm once (avoids callback accumulation)
	init_llm(api_key=api_key)

	# Strip secator-internal per-message fields before sending to the model. Each
	# message may carry bookkeeping keys ChatHistory owns (e.g. `_token_count` /
	# `_token_model`, its per-model token cache) — not part of the chat-completion
	# message schema. Some providers reject them or, worse, silently return an empty
	# response when a message has unknown keys (observed with a local model). We can't
	# use litellm's drop_params (it only drops top-level params, not nested message
	# sub-fields), so copy each message without the `_`-prefixed keys. The originals
	# are untouched, so the caller's token cache / accounting keep working.
	llm_messages = [
		{k: v for k, v in m.items() if not str(k).startswith('_')}
		for m in messages
	]

	kwargs = dict(
		model=model,
		messages=llm_messages,
		temperature=temperature,
		# Let litellm drop params the model rejects instead of raising, e.g. a
		# temperature other than 1 while reasoning / thinking is active.
		drop_params=True,
		api_base=api_base,
	)
	# OAuth2: (re)checked on every call so a long run never sends an expired token.
	oauth2_cfg = None if api_key else resolve_ai_profile(profile)
	use_oauth2 = bool(oauth2_cfg) and _uses_oauth2(api_base, api_key, oauth2_cfg)
	oauth2_retried = False
	if use_oauth2:
		if _normalize_api_base(api_base)[1]:
			raise ValueError('addons.ai.api_base must be https:// (http:// only for a bare localhost host) with OAuth2.')
		kwargs["api_key"] = _oauth2_tokens.get(oauth2_cfg)
	# HARD DEBUG (ALL COMPLETE MESSAGES EXCEPT SYSPROMPT)
	# Remove only when we have a better way to show this
	if tools is not None:
		kwargs["tools"] = tools  # tool_choice left unset: "auto" is the default with tools

	# Normalize assistant messages that have tool_calls but no 'content' key.
	# litellm's trim_messages crashes with KeyError: 'content' on such messages.
	# An empty content on a tool-call turn (older saved histories) becomes None too:
	# some Chat-to-Responses converters treat "" as a text message and drop the calls.
	for msg in kwargs["messages"]:
		if msg.get("role") == "assistant" and ("content" not in msg or (msg.get("tool_calls") and msg["content"] == "")):
			msg["content"] = None

	# Sanitize orphan tool_use blocks (Anthropic requires every tool_use to have
	# a matching tool_result). Safety net in case the caller bypassed ChatHistory.
	_repair_orphan_tool_uses(kwargs["messages"])

	# 400s are non-transient (malformed request, context_length_exceeded, ...) —
	# handled separately below and NOT in this transient-retry tuple.
	retryable = (
		litellm.InternalServerError, litellm.RateLimitError,
		litellm.ServiceUnavailableError, litellm.APIConnectionError,
		litellm.APIError
	)
	for attempt in range(1, max_retries + 1):
		# Chat Completions tool messages have no `name` and strict OpenAI-compatible
		# endpoints reject it; litellm's other routes match tool results by
		# `tool_call_id` (Gemini recovers the name from it). Done per attempt, as the
		# orphan repair inserts tool messages (these dicts are already copies).
		for msg in kwargs["messages"]:
			if msg.get("role") == "tool":
				msg.pop("name", None)
		try:
			response = litellm.completion(**kwargs)
			break
		except litellm.BadRequestError as e:
			# 400s fail fast, except the orphan tool_use case which we repair
			# and retry without backoff, while attempts remain (else raise it).
			err_str = str(e)
			if 'tool_use' in err_str and 'tool_result' in err_str:
				repaired = _repair_orphan_tool_uses(kwargs["messages"])
				if repaired and attempt < max_retries:
					console.print(Warning(
						message=f"Repaired {repaired} orphan tool_use block(s); retrying LLM call."))
					continue
			console.print(Error(message=f"LLM call failed with non-retryable 400: {e}"))
			raise
		except retryable as e:
			if attempt < max_retries:
				wait = 2 ** attempt
				console.print(Warning(
					message=f"LLM call failed (attempt {attempt}/{max_retries}): {e}. Retrying in {wait}s..."))
				time.sleep(wait)
			else:
				raise
		except litellm.AuthenticationError as e:
			if use_oauth2 and not oauth2_retried and attempt < max_retries:
				# Token revoked or expired early: refetch once and retry.
				oauth2_retried = True
				kwargs["api_key"] = _oauth2_tokens.get(oauth2_cfg, force=True)
				continue
			console.print(Error(message=e))
			hint = (f'Check the oauth2_client_id / oauth2_client_secret / oauth2_scope of AI profile "{oauth2_cfg["name"]}"'
				if use_oauth2
				else 'Please set a valid API key with `secator config set addons.ai.api_key <KEY>`')
			console.print(Error(message=hint))
			raise

	# An empty `choices` list comes back without an exception: raise one that carries
	# the response fields saying why (stop reason, provider error, usage).
	if not response.choices:
		raw = response.model_dump()
		raw['original_response'] = getattr(response, '_hidden_params', {}).get('original_response')
		keys = ('id', 'model', 'finish_reason', 'stop_reason', 'error', 'usage', 'original_response')
		details = {k: raw[k] for k in keys if raw.get(k)}
		raise ValueError(f"LLM returned no choices for model {model}: {str(details)[:2000]}")
	message = response.choices[0].message
	content = message.content or ""
	usage = None

	if hasattr(response, 'usage') and response.usage:
		try:
			cost = litellm.completion_cost(completion_response=response)
		except Exception:
			cost = None

		usage = {
			"tokens": response.usage.total_tokens,
			"prompt_tokens": getattr(response.usage, "prompt_tokens", None),
			"completion_tokens": getattr(response.usage, "completion_tokens", None),
			# litellm maps every provider's cache reads (e.g. Anthropic cache_read_input_tokens) here.
			"cached_tokens": getattr(getattr(response.usage, "prompt_tokens_details", None), "cached_tokens", None),
			"cost": cost,
		}
	else:
		# usage missing/empty (streaming, some models) — estimate so the call
		# is still metered instead of silently counting 0 tokens.
		usage = _estimate_usage(model, kwargs["messages"], content, getattr(message, 'tool_calls', None))
		console.print(Warning(
			message=f"LLM response missing usage; estimated ~{usage['tokens']} tokens for metering."))

	# Get tool calls
	tool_calls = getattr(message, 'tool_calls', None) or []
	# finish_reason distinguishes a genuinely-empty turn from a truncated one
	# (finish_reason == "length") — the caller uses it to report the real cause
	# of an empty response instead of blaming tool-calling support.
	finish_reason = getattr(response.choices[0], 'finish_reason', None)

	return {"content": content, "usage": usage, "tool_calls": tool_calls, "finish_reason": finish_reason}


# Some models (Hermes-style / XML tool-calling) emit tool calls as TEXT in the
# message content instead of native structured `tool_calls`. litellm hands that
# text back as `content` with an empty `tool_calls`. These regexes recover the
# calls so the loop can dispatch them like native ones.
_TOOL_CALL_BLOCK_RE = re.compile(r'<tool_call>\s*(.*?)\s*</tool_call>', re.DOTALL | re.IGNORECASE)
_FUNCTION_RE = re.compile(r'<function=([^>\s]+)\s*>', re.IGNORECASE)
_PARAM_RE = re.compile(
	r'<parameter=([^>\s]+)\s*>(.*?)(?=<parameter=|</parameter>|</function>|</tool_call>|\Z)',
	re.DOTALL | re.IGNORECASE,
)


def _coerce_param_value(raw: str) -> Any:
	"""A <parameter> value may be JSON (number/bool/object/array/quoted string) or
	plain text. Try JSON; fall back to the raw string on failure."""
	if raw == "":
		return raw
	try:
		return json.loads(raw)
	except (json.JSONDecodeError, ValueError):
		return raw


def _parse_tool_call_block(block: str, index: int):
	"""Parse one <tool_call> body into a litellm-shaped call, or None if unparseable.

	Supports both bodies models emit:
	  * XML-style:  <function=NAME> <parameter=KEY>VALUE</parameter> ...
	  * JSON-style: {"name": "NAME", "arguments": {...}}
	"""
	name = None
	args: Dict = {}
	fn = _FUNCTION_RE.search(block)
	if fn:
		name = fn.group(1).strip()
		for key, raw in _PARAM_RE.findall(block):
			args[key.strip()] = _coerce_param_value(raw.strip())
	else:
		try:
			data = json.loads(block.strip())
		except (json.JSONDecodeError, TypeError, ValueError):
			return None
		if not isinstance(data, dict):
			return None
		name = data.get("name") or data.get("function")
		args = data.get("arguments") or data.get("parameters") or {}
		if isinstance(args, str):
			try:
				args = json.loads(args)
			except (json.JSONDecodeError, ValueError):
				pass
	if not name:
		return None
	# Shape it exactly like a native litellm tool call (attribute access + JSON-string
	# arguments) so _process_tool_calls / _add_assistant_to_history consume it unchanged.
	return SimpleNamespace(
		id=f"textcall_{index}_{name}",
		type="function",
		function=SimpleNamespace(name=name, arguments=json.dumps(args)),
	)


def parse_text_tool_calls(content: Optional[str]) -> Tuple[List, Optional[str]]:
	"""Recover tool calls a model emitted as text inside `content`.

	Returns (tool_calls, cleaned_content):
	  * tool_calls — litellm-shaped calls (empty if none found / all unparseable);
	  * cleaned_content — `content` with every consumed <tool_call> block stripped,
	    so the raw XML is not shown to the user. Unchanged when nothing is parsed.
	Never raises: malformed blocks are skipped.
	"""
	if not content or '<tool_call>' not in content.lower():
		return [], content
	tool_calls = [
		call for i, block in enumerate(_TOOL_CALL_BLOCK_RE.findall(content))
		if (call := _parse_tool_call_block(block, i)) is not None
	]
	if not tool_calls:
		return [], content
	cleaned = _TOOL_CALL_BLOCK_RE.sub('', content).strip()
	return tool_calls, cleaned


def _format_token_breakdown(token_count, ctx_window, by_role):
	"""Format the token/context-window/per-role strings shared by the LLM status
	spinner and the prompt_user title recap."""
	token_str = format_token_count(token_count, icon='arrow_up', compact=True)
	ctx_str = format_token_count(ctx_window, compact=True)
	role_parts = []
	for role in ('system', 'user', 'assistant', 'tool'):
		if role in by_role:
			role_parts.append(f'[orange4]{role}[/]:{format_token_count(by_role[role], compact=True)}')
	role_str = ' | '.join(role_parts)
	return token_str, ctx_str, role_str


def format_llm_status(token_count, ctx_window, by_role):
	"""Format a rich status message for LLM calls with token counts and a spinner message."""
	token_str, ctx_str, role_str = _format_token_breakdown(token_count, ctx_window, by_role)
	return (
		f"[bold orange3]{random.choice(LLM_SPINNER_MESSAGES)}[/]"
		f" [gray42] • {token_str}/[dim red]{ctx_str}[/] ({role_str})[/]"
	)


def _normalize_api_base(raw):
	"""Validate/normalize a user-entered API base. Returns ``(base, error|None)``."""
	base = (raw or '').strip().rstrip('/')
	if not base:
		return '', 'API base cannot be empty.'
	from urllib.parse import urlparse
	if base.startswith('https://'):
		try:
			host = urlparse(base).hostname
		except ValueError:
			host = None
		return (base, None) if host else ('', 'Invalid API base URL.')
	# http:// is allowed ONLY for a bare localhost dev gateway. Resolve the REAL
	# destination via urlparse (not string-splitting): `http://localhost@evil` parses
	# to host `evil`, and embedded userinfo (`user:pass@`) must be rejected — otherwise
	# the Bearer key would be sent in cleartext to a remote host.
	try:
		parsed = urlparse(base)
	except ValueError:
		return '', 'Invalid API base URL.'
	if (parsed.scheme == 'http'
			and parsed.hostname in ('localhost', '127.0.0.1')
			and not parsed.username and not parsed.password):
		return base, None
	return '', 'API base must be https:// (http:// allowed only for a bare localhost host).'


def _ssl_verify():
	"""Whether to verify TLS certs for the setup model-listing call.

	Honors the SAME ``SSL_VERIFY`` env knob litellm reads for the inference call, so a
	gateway with a self-signed / non-public cert that works for the AI task (``SSL_VERIFY=False``)
	also works here. Falsey = ``false``/``0``/``no``/``off`` (any case); default is verify.
	"""
	val = os.environ.get('SSL_VERIFY')
	if val is None:
		return True
	return val.strip().lower() not in ('false', '0', 'no', 'off', '')


def fetch_openai_compatible_models(api_base, api_key, timeout=15):
	"""List model ids from an OpenAI-compatible endpoint's ``/models`` route.

	A custom base may or may not already include ``/v1``, so try ``{base}/models``
	then ``{base}/v1/models``. Returns a sorted list of model-id strings; raises on
	network / auth / parse failure so the caller can fall back to manual entry.

	TLS verification follows ``SSL_VERIFY`` (same knob as the inference call), so a
	gateway with a self-signed cert lists models iff it also runs.
	"""
	from secator.requests import requests
	verify = _ssl_verify()
	if not verify:
		# Silence the per-request urllib3 InsecureRequestWarning spam at setup time.
		import urllib3
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	base = (api_base or '').rstrip('/')
	candidates = [f'{base}/models']
	if not base.endswith('/v1'):
		candidates.append(f'{base}/v1/models')
	headers = {'Authorization': f'Bearer {api_key}', 'Accept': 'application/json'}
	last_err = None
	for url in candidates:
		try:
			resp = requests.get(url, headers=headers, timeout=timeout, verify=verify)
			resp.raise_for_status()
			data = resp.json()
		except Exception as e:  # noqa: BLE001 - try the next candidate, surface at the end
			last_err = e
			continue
		items = data.get('data') if isinstance(data, dict) else data
		ids = sorted({
			str(m['id']) for m in (items or [])
			if isinstance(m, dict) and m.get('id')
		})
		if ids:
			return ids
		last_err = ValueError(f'no models listed at {url}')
	raise last_err or ValueError('could not list models from the endpoint')


def load_ai_providers():
	"""Named OpenAI-compatible providers offered in `ai setup`, on top of LiteLLM.

	Merges a bundled registry (``secator/ai/providers.json``) with an optional user
	file (``<SECATOR_DIRS_DATA>/ai_providers.json``); the user file overrides bundled
	entries by ``name``. This lets any gateway/router be added by a small JSON entry —
	no code. Per-entry schema: ``name``, ``label``, ``api_base`` (https, OpenAI-compatible),
	optional ``docs``, ``key_hint`` and ``litellm_provider`` (native LiteLLM route used as the
	model prefix instead of ``openai/``). A malformed/missing file is skipped, never fatal.
	"""
	from pathlib import Path
	providers = {}
	bundled = Path(__file__).parent / 'providers.json'
	user = Path(str(CONFIG.dirs.data)) / 'ai_providers.json'
	for path in (bundled, user):
		try:
			if not path.exists():
				continue
			data = json.loads(path.read_text())
			for p in data.get('providers', []):
				if not (isinstance(p, dict) and p.get('name') and p.get('api_base')):
					continue
				# SECURITY: a registry entry's base must pass the SAME https-or-localhost
				# rule as a hand-entered base - else an http://remote/v1 entry would ship
				# the Bearer key in cleartext when selected.
				norm, err = _normalize_api_base(p['api_base'])
				if err:
					console.print(f"[dim]  (skipped provider {p['name']}: {err})[/]")
					continue
				providers[p['name']] = {**p, 'api_base': norm}
		except Exception as e:  # noqa: BLE001 - a bad provider file must not break setup
			console.print(f"[dim]  (skipped provider file {path}: {e})[/]")
	return list(providers.values())


# Short, well-known tokens to upper-case (not Title-case) when prettifying a
# snake_case provider id (so `vertex_ai` -> "Vertex AI", not "Vertex Ai").
_PROVIDER_ACRONYMS = {'ai', 'aws', 'gcp', 'api', 'llm', 'xai', 'ibm', 'hf'}


def pretty_provider(provider_id):
	"""snake_case / kebab-case provider id -> Normal Case, Capitalized.

	e.g. ``vertex_ai`` -> ``Vertex AI``, ``text-completion-openai`` -> ``Text Completion Openai``.
	"""
	return ' '.join(
		w.upper() if w in _PROVIDER_ACRONYMS else w.capitalize()
		for w in str(provider_id).replace('-', '_').split('_') if w
	) or str(provider_id)


# Model modes (litellm metadata) that are NOT text chat: such models are hidden from
# `ai setup`, and so are providers whose every known model is one of these.
_NON_CHAT_MODES = {
	'audio_transcription', 'audio_speech', 'image_generation', 'embedding',
	'rerank', 'moderation',
}

# Rows the model table prints at once; the others stay reachable by filtering.
_MODEL_ROWS = 40

# Credential fields of the `ai setup` state, and the config key each one is saved to.
_CRED_KEYS = {
	'api_key': 'api_key', 'endpoint': 'oauth2_endpoint', 'client_id': 'oauth2_client_id',
	'client_secret': 'oauth2_client_secret', 'scope': 'oauth2_scope',
}


class _Back(Exception):
	"""A setup prompt got ``b`` (or Esc in a menu): go back one step."""


class _Quit(Exception):
	"""A setup prompt got ``q``: leave without saving."""


def _tty():
	import sys
	return sys.stdin.isatty()


def _ask(label, default=None, password=False, enter=None, help=None):
	"""Prompt once; Enter returns ``default``. ``b`` and ``q`` raise :class:`_Back` / :class:`_Quit`.

	``enter`` says what Enter does (``[Enter = keep …]``, e.g. with a masked secret); ``''`` hides it.
	"""
	from rich.prompt import Prompt
	if help:
		console.print(f"  [dim]{help}[/]")
	if enter is None and default:
		enter = f'keep {default}'
	hint = f" [dim]\\[Enter = {escape(enter)}][/]" if enter else ''
	raw = Prompt.ask(f"  [bold cyan]{label}[/]{hint}", default=default, show_default=False, password=password)
	value = (raw or '').strip()
	if value.lower() in ('b', 'back'):
		raise _Back
	if value.lower() in ('q', 'quit', 'exit'):
		raise _Quit
	return value


def _yes(label, default):
	answer = _ask(f"{label} [dim]({'Y/n' if default else 'y/N'})[/]", default='y' if default else 'n', enter='')
	return answer.lower().startswith('y')


def _choose(title, options, default=0):
	"""Pick one of ``options`` (labels): arrow keys on a terminal, a numbered prompt otherwise."""
	if _tty():
		from secator.rich import InteractiveMenu
		menu = InteractiveMenu(
			f"  [bold]{title}[/]", [{'label': o} for o in options], selected=default,
			description='Esc = back · Ctrl+C = quit')
		picked = menu.show()
		if picked is None:
			raise _Quit if menu.interrupted else _Back  # Ctrl+C quits, Esc goes back
		return picked[0]
	console.print(f"  [bold]{title}[/]")
	for i, option in enumerate(options, 1):
		console.print(f"    [cyan]{i}[/] {option}")
	while True:
		raw = _ask('Choice', default=str(default + 1), enter=options[default])
		if raw.isdigit() and 1 <= int(raw) <= len(options):
			return int(raw) - 1
		match = [i for i, o in enumerate(options) if raw.lower() in o.lower()]
		if len(match) == 1:
			return match[0]
		console.print(f"  [yellow]Type a number from 1 to {len(options)}.[/]")


def _short_error(e, *secrets, limit=300):
	"""The provider's error as one capped line, without a traceback or secrets, escaped for rich markup."""
	detail = None
	try:
		err = e.response.json().get('error')
		detail = err.get('message') if isinstance(err, dict) else err
	except Exception:  # noqa: BLE001 - not an HTTP error with a JSON body
		pass
	msg = ' '.join(f'{e} ({detail})'.split() if detail else str(e).split()) or type(e).__name__
	for secret in secrets:
		if secret:
			msg = msg.replace(secret, mask_secret(secret))
	return escape(msg if len(msg) <= limit else msg[:limit] + '…')


def _explain_error(e, state, *secrets):
	"""A short, actionable message: a rejected key or token says so, with the provider's docs."""
	status = getattr(getattr(e, 'response', None), 'status_code', None)
	if status is None:
		found = re.search(r'\b(401|403)\b', str(e))
		status = int(found.group(1)) if found else None
	if status in (401, 403):
		if state['cred']['method'] == 'oauth2' and not state.get('token'):
			return f"Client ID / secret rejected by the token URL ({status})."
		what = 'OAuth2 token' if state['cred']['method'] == 'oauth2' else 'Key'
		docs = state['gateway'].get('docs')
		return f"{what} rejected by {state['label']} ({status})." + (f" Check it at {escape(docs)}" if docs else '')
	return f"{state['label']} said: {_short_error(e, *secrets)}"


def _model_info(model):
	"""LiteLLM's metadata for ``model`` (price, context, flags), or ``{}`` when it has none."""
	import litellm
	parts = model.split('/')
	# `openai/anthropic/claude-x` (a gateway route) is priced as `anthropic/claude-x`, then `claude-x`.
	for i in range(len(parts)):
		info = litellm.model_cost.get('/'.join(parts[i:]))
		if info:
			return info
	return {}


def _is_chat_model(model):
	return _model_info(model).get('mode') not in _NON_CHAT_MODES


def _chat_capable(provider):
	"""Keep a provider unless EVERY model with known metadata is non-chat.

	Lenient on purpose: providers whose models carry no mode metadata (gateways, newer
	vendors) are kept; only pure audio/image/embedding vendors (polly, deepgram, voyage...)
	are dropped from the list."""
	import litellm
	modes = [m for m in (_model_info(n).get('mode') for n in litellm.models_by_provider.get(provider, [])) if m]
	return not modes or any(m not in _NON_CHAT_MODES for m in modes)


def _with_route(route, model_id):
	return model_id if model_id.startswith(f'{route}/') else f'{route}/{model_id}'


def _same_model(model, saved):
	"""Whether ``model`` is the saved model, which may lack its provider prefix (``claude-x``)."""
	return bool(saved) and saved in (model, model.split('/', 1)[-1])


def _provider_catalog(provider):
	"""The models bundled with LiteLLM for ONE provider (its price table)."""
	import litellm
	return sorted({_with_route(provider, m) for m in litellm.models_by_provider.get(provider, [])})


def _list_provider_models(provider, api_key):
	"""Live model ids of a LiteLLM provider, or ``None`` when LiteLLM cannot list them.

	Uses the provider lister behind ``litellm.get_valid_models(check_provider_endpoint=True)``
	directly: ``get_valid_models`` turns every failure, a rejected key included, into an empty
	list, while the wizard must tell the user why. Raises on failure.
	"""
	from litellm.types.utils import LlmProviders
	from litellm.utils import ProviderConfigManager
	try:
		lister = ProviderConfigManager.get_provider_model_info(model=None, provider=LlmProviders(provider))
	except ValueError:
		return None
	if lister is None:
		return None
	try:
		ids = lister.get_models(api_key=api_key or None)
	except NotImplementedError:  # e.g. vertex_ai: has a lister class without a listing
		return None
	return sorted({_with_route(provider, m) for m in ids})


def _newest_first(models):
	"""Alphabetical by family, highest version first within it (``gpt-5`` before ``gpt-4o``)."""
	return sorted(models, key=lambda m: [-int(t) if t.isdigit() else t for t in re.split(r'(\d+)', m.lower())])


def _fmt_price(per_token):
	return f'${per_token * 1e6:,.2f}' if isinstance(per_token, (int, float)) else '—'


def _fmt_ctx(tokens):
	if not isinstance(tokens, int) or tokens <= 0:
		return '—'
	return f'{tokens / 1e6:g}M' if tokens >= 1e6 else f'{tokens // 1000}k' if tokens >= 1000 else str(tokens)


def _fmt_flag(value):
	return {True: '✓', False: '✗'}.get(value, '—')


def _print_models(models, default=None, title=''):
	"""Print ``models`` as a numbered table: context, price per 1M tokens, tool / reasoning support."""
	from rich.table import Table
	table = Table(box=None, padding=(0, 1), header_style='dim')
	table.add_column('#', justify='right', style='dim')
	table.add_column('Model')
	for col in ('Context', 'In $/1M', 'Out $/1M'):
		table.add_column(col, justify='right')
	table.add_column('Tools', justify='center')
	table.add_column('Reasoning', justify='center')
	for i, m in enumerate(models[:_MODEL_ROWS], 1):
		info = _model_info(m)
		route, _, rest = m.rpartition('/')
		name = f'[dim]{escape(route)}/[/]{escape(rest)}' if route else escape(m)
		if m == default:
			name = f'[bold cyan]{escape(m)}[/] [cyan]● current[/]'
		table.add_row(
			str(i), name, _fmt_ctx(info.get('max_input_tokens')),
			_fmt_price(info.get('input_cost_per_token')), _fmt_price(info.get('output_cost_per_token')),
			_fmt_flag(info.get('supports_function_calling')), _fmt_flag(info.get('supports_reasoning')),
		)
	console.print(f"  [dim]{len(models)} model{'s' if len(models) != 1 else ''}{escape(title)}[/]")
	console.print(table, highlight=False)
	if len(models) > _MODEL_ROWS:
		console.print(f"  [dim]… {len(models) - _MODEL_ROWS} more: type text to filter.[/]")


def _pick_model(models, route, default=None, label='Model', shown=None):
	"""Choose a model by number, id or filter text; Enter keeps ``default``. Returns ``(model, shown)``.

	With no ``models`` (nothing could be listed), any typed id is accepted; otherwise an unlisted
	id is used after a confirmation. ``shown`` is the table already on screen (numbers refer to its
	rows); without it the full table is printed first.
	"""
	keep = f"keep {default.split('/', 1)[-1]}" if default else None
	if not models:
		while True:
			raw = _ask(f"{label} id", default=default, enter=keep, help='Type the model id, e.g. my-model.')
			if raw:
				return (raw if raw == default else _with_route(route, raw)), []
	if shown is None:
		shown = models
		_print_models(models, default)
	while True:
		raw = _ask(label, default=default, enter=keep, help='Type a number, an id, or text to filter the list.')
		if not raw:
			shown = models
			_print_models(models)
			continue
		if raw == default:
			return default, shown
		# A number picks a shown row; any other number is filter text (e.g. "405").
		if raw.isdigit() and 1 <= int(raw) <= min(len(shown), _MODEL_ROWS):
			return shown[int(raw) - 1], shown
		low = raw.lower()
		exact = [m for m in models if low in (m.lower(), m.split('/', 1)[-1].lower())]
		if exact:
			return exact[0], shown
		matches = [m for m in models if low in m.lower()]
		# Filter text picks its only match; a full id (with a "/") must match exactly.
		if len(matches) == 1 and '/' not in raw:
			return matches[0], shown
		# Not listed (e.g. newer than LiteLLM's bundled list): the typed id can still be used.
		if len(matches) == 1:
			shown = matches
			_print_models(matches, default, f' matching "{raw}"')
		if len(matches) <= 1:
			if _yes(f'"{escape(raw)}" is not listed. Use it as the model id?', default=False):
				return _with_route(route, raw), shown
			continue
		shown = matches
		_print_models(matches, default, f' matching "{raw}"')


def _settings_rows(state):
	"""The settings of ``state`` as (name, value) rows, secrets masked."""
	cred = state['cred']
	rows = [('Provider', state['label'])]
	if state['base']:
		rows.append(('API base', escape(mask_url(state['base']))))
	if cred['method'] == 'oauth2':
		rows += [
			('Auth', 'OAuth2 client credentials'), ('Client ID', escape(cred['client_id'])),
			('Client secret', escape(mask_secret(cred['client_secret']))), ('Token URL', escape(mask_url(cred['endpoint']))),
		]
	else:
		rows.append(('API key', escape(mask_secret(cred['api_key'])) if cred['api_key'] else "[dim]provider's env vars[/]"))
	rows += [('Model', escape(state['model'] or 'not set')), ('Intent model', escape(state['intent'] or 'not set'))]
	if state.get('profile', DEFAULT_PROFILE) != DEFAULT_PROFILE or CONFIG.addons.ai.profiles:
		rows.insert(0, ('Profile', escape(state.get('profile') or DEFAULT_PROFILE)))
	return rows


def _print_panel(title, rows, style='cyan'):
	from rich.panel import Panel
	from rich.table import Table
	grid = Table.grid(padding=(0, 2))
	grid.add_column(style='dim')
	grid.add_column()
	for name, value in rows:
		grid.add_row(name, value)
	console.print()
	console.print(Panel(grid, title=f'[bold]{title}[/]', title_align='left', border_style=style, expand=False))


def _step_header(state, title):
	num, total = state['step']
	step = f"[bold cyan]Step {num} of {total}[/] [dim]·[/] " if total > 1 else ''
	console.print(f"\n  {step}[bold]{title}[/]  [dim]b = back · q = quit[/]")


def _provider_entries():
	"""Every provider offered: LiteLLM's (on their default base), the registry gateways, a custom base."""
	import litellm
	gateways = load_ai_providers()
	# A registry gateway named like a LiteLLM provider (e.g. openrouter) is listed once, as the gateway.
	names = {g['name'] for g in gateways}
	lite = sorted(p for p in litellm.models_by_provider if p not in names and _chat_capable(p))
	return ([('lite', p, pretty_provider(p)) for p in lite]
	        + [('gateway', g, escape(g.get('label') or g['name'])) for g in gateways]
	        + [('custom', None, 'Custom')])


def _entry_state(entry, base=''):
	"""The provider part of the state for one entry (``base`` only matters for a custom one)."""
	kind, val, label = entry
	if kind == 'lite':
		return {'kind': kind, 'label': label, 'gateway': {}, 'route': val, 'base': '', 'catalog': val}
	if kind == 'gateway':
		# Only a native route has a LiteLLM catalog of its own: a plain `openai/` gateway is not OpenAI.
		route = val.get('litellm_provider') or 'openai'
		return {'kind': kind, 'label': label, 'gateway': val, 'route': route, 'base': val['api_base'],
		        'catalog': val.get('litellm_provider')}
	return {'kind': kind, 'label': label, 'gateway': {}, 'route': 'openai', 'base': base, 'catalog': None}


def _saved_entry(entries, saved):
	"""The provider entry the saved config uses: same route on its default base, or the same base."""
	for entry in entries:
		kind, val, _ = entry
		if (kind == 'lite' and (val, '') == (saved['route'], saved['base'])) or (
				kind == 'gateway' and val['api_base'] == saved['base']):
			return entry
	return entries[-1] if saved['base'] else None


def _blank_cred(method='key'):
	return {'method': method, 'api_key': '', 'endpoint': '', 'client_id': '', 'client_secret': '', 'scope': ''}


def _same_target(state, saved):
	return (state['route'], state['base']) == (saved['route'], saved['base'])


def _step_menu(state, saved):
	"""Re-run: start from the saved setup and pick what to change ("Change model" by default)."""
	_print_panel('Current AI setup', _settings_rows(state))
	actions = [
		('Change model', [_step_model, _step_save]),
		('Change provider / API base', [_step_provider, _step_auth, _step_model, _step_intent, _step_save]),
		('Change credentials', [_step_auth, _step_save]),
		('Change intent model', [_step_intent, _step_save]),
		*([('Switch profile', [_step_switch_profile])] if CONFIG.addons.ai.profiles else []),
		('Add profile', [_step_provider, _step_auth, _step_model, _step_intent, _step_save]),
		('Done', []),
	]
	picked = _choose('What do you want to change?', [a[0] for a in actions])
	steps = actions[picked][1]
	state['add_profile'] = actions[picked][0] == 'Add profile'
	# OAuth2 without a saved token URL: the secret is only sent once the user confirmed one.
	cred = state['cred']
	if cred['method'] == 'oauth2' and not cred['endpoint'] and steps and _step_auth not in steps:
		console.print("  [yellow]Your OAuth2 setup has no token URL yet: confirm it first.[/]")
		steps = [_step_auth] + steps
	return steps


def _step_provider(state, saved):
	"""Pick a LiteLLM provider (default base), a gateway from the registry, or a custom base."""
	from rich.columns import Columns
	_step_header(state, 'Provider')
	entries = _provider_entries()

	def show(subset):
		cells = [f"[dim]{i:>3}[/] {label}" for i, (kind, _, label) in subset if kind == 'lite']
		if cells:
			console.print(Columns(cells, column_first=True, padding=(0, 2)))
		for i, (kind, val, label) in subset:
			if kind == 'gateway':
				console.print(f"  [dim]{i:>3}[/] {label} [dim]· gateway · {escape(val['api_base'])}[/]")
			elif kind == 'custom':
				console.print(f"  [dim]{i:>3}[/] {label} [dim]· your own OpenAI-compatible URL[/]")

	current = _saved_entry(entries, saved)
	default = current[2] if current else None
	numbered = list(enumerate(entries, 1))
	show(numbered)
	while True:
		raw = _ask('Provider', default=default, help='Type a number, or text to filter the list.')
		if raw.isdigit() and 1 <= int(raw) <= len(entries):
			entry = entries[int(raw) - 1]
			break
		matches = [(i, e) for i, e in numbered if raw and raw.lower() in e[2].lower()]
		exact = [e for _, e in matches if e[2].lower() == raw.lower()]
		if len(matches) == 1 or exact:
			entry = exact[0] if exact else matches[0][1]
			break
		if matches:
			show(matches)
		else:
			console.print(f'  [yellow]No provider matches "{escape(raw)}".[/]')
	base = ''
	if entry[0] == 'custom':
		while True:
			base, err = _normalize_api_base(_ask(
				'API base URL', default=saved['base'] or None, enter=saved['base'] and f"keep {mask_url(saved['base'])}",
				help='The OpenAI-compatible URL, e.g. https://llm.example.com/v1'))
			if not err:
				break
			console.print(f"  [red]{err}[/]")
	state.update(_entry_state(entry, base))
	state.pop('models', None)
	state.pop('shown', None)
	# Never offer one endpoint's credentials to another one.
	state['cred'] = dict(saved['cred']) if _same_target(state, saved) else _blank_cred()


def _ask_key(state, cred):
	optional = state['kind'] == 'lite'
	keep = mask_secret(cred['api_key']) if cred['api_key'] else None
	help = 'Paste your API key.' + (" Leave empty to use the provider's environment variables." if optional else '')
	if state['gateway'].get('key_hint'):
		help += f" It usually starts with {escape(state['gateway']['key_hint'])}"
	while True:
		raw = _ask('API key', default=keep, password=_tty(), help=help)
		key = cred['api_key'] if keep and raw == keep else raw
		if key or optional:
			# Switching from OAuth2 to a key drops the OAuth2 settings (they would show as the method).
			dropped = {f: '' for f in _CRED_KEYS if f != 'api_key'} if cred['method'] == 'oauth2' else {}
			return {**cred, **dropped, 'method': 'key', 'api_key': key}
		console.print("  [red]This endpoint needs an API key.[/]")


def _ask_oauth2(state, cred):
	client_id = ''
	while not client_id:
		client_id = _ask('Client ID', default=cred['client_id'] or None, help='OAuth2 client credentials for this endpoint.')
	url = cred['endpoint'] or default_oauth2_token_url(state['base'])
	while True:
		endpoint, err = _normalize_api_base(_ask(
			'Token URL', default=url, enter=f'keep {mask_url(url)}',
			help='Where the client ID and secret are exchanged for an access token.'))
		if not err:
			break
		console.print(f"  [red]{err}[/]")
	# The saved secret is only ever sent to the token URL it was saved for (or, for an older setup
	# without one, to the default the user just confirmed in this prompt).
	saved_secret = cred['client_secret'] if endpoint == url else ''
	keep = mask_secret(saved_secret) if saved_secret else None
	secret = ''
	while not secret:
		raw = _ask('Client secret', default=keep, password=_tty())
		secret = saved_secret if keep and raw == keep else raw
	return {**cred, 'method': 'oauth2', 'client_id': client_id, 'client_secret': secret, 'endpoint': endpoint}


def _bearer(state):
	"""What authenticates the calls: the API key, or an OAuth2 access token fetched once."""
	cred = state['cred']
	if cred['method'] != 'oauth2':
		return cred['api_key']
	if not state.get('token'):
		with maybe_status('[bold cyan]Getting an OAuth2 token…[/]', spinner='dots'):
			state['token'] = OAuth2TokenCache._fetch(
				cred['endpoint'], cred['client_id'], cred['client_secret'], cred['scope'])[0]
	return state['token']


def _fetch_models(state):
	"""List the models live, which also checks the credentials. Raises on failure; ``None`` = no listing."""
	token = _bearer(state)
	with maybe_status(f"[bold cyan]Fetching models from {state['label']}…[/]", spinner='dots'):
		if state['kind'] == 'lite':
			return _list_provider_models(state['route'], token)
		return [f"{state['route']}/{i}" for i in fetch_openai_compatible_models(state['base'], token)]


def _set_models(state, live):
	models = [m for m in live if _is_chat_model(m)] if live is not None else None
	if not models and state['catalog']:  # nothing listed, or nothing to chat with in the listing
		models = _provider_catalog(state['catalog']) if state['catalog'] else []
		if models:
			console.print(f"  [dim]Showing LiteLLM's bundled list for {state['label']}.[/]")
	state['models'] = _newest_first(m for m in models or [] if _is_chat_model(m))
	state.pop('shown', None)


def _step_auth(state, saved):
	"""Credentials: an API key, or OAuth2 client credentials for a gateway / custom base."""
	_step_header(state, 'Credentials')
	cred = state['cred']
	method = 'key'
	if state['kind'] != 'lite':
		options = ['API key', 'OAuth2 (client ID + secret)']
		method = ('key', 'oauth2')[_choose('How do you sign in?', options, default=int(cred['method'] == 'oauth2'))]
	while True:
		new = _ask_oauth2(state, cred) if method == 'oauth2' else _ask_key(state, cred)
		state.update(cred=new, token=None)
		try:
			live = _fetch_models(state)
		except Exception as e:  # noqa: BLE001 - explained to the user, who retries or goes on
			console.print(f"  [red]✗ {_explain_error(e, state, new['api_key'], new['client_secret'], state.get('token'))}[/]")
			if _yes('Try again?', default=True):
				# Prefill what was typed, except the rejected secret: Enter keeps the saved one.
				same_url = new['endpoint'] == (cred['endpoint'] or default_oauth2_token_url(state['base']))
				cred = {**new, 'api_key': cred['api_key'], 'client_secret': cred['client_secret'] if same_url else ''}
				continue
			live = None
		else:
			what = 'OAuth2 token' if method == 'oauth2' else 'Key'
			if live and _bearer(state):
				console.print(f"  [green]✓ {what} accepted: {len(live)} model{'s' if len(live) != 1 else ''} available.[/]")
			elif live is None and _bearer(state):
				console.print(f"  [dim]{state['label']} does not list models: the {what.lower()} is checked at the end.[/]")
		_set_models(state, live)
		return


def _ensure_models(state):
	"""List the models with the saved credentials when no earlier step did (a quick re-run)."""
	if 'models' not in state:
		try:
			live = _fetch_models(state)
		except Exception as e:  # noqa: BLE001 - fall back to the bundled list
			cred = state['cred']
			console.print(f"  [yellow]{_explain_error(e, state, cred['api_key'], cred['client_secret'], state.get('token'))}[/]")
			live = None
		_set_models(state, live)


def _step_model(state, saved):
	_step_header(state, 'Model')
	_ensure_models(state)
	# Enter keeps the saved model when the provider did not change, listed or not.
	default = None
	if _same_target(state, saved) and saved['model']:
		default = next((m for m in state['models'] if _same_model(m, saved['model'])), saved['model'])
	state['model'], state['shown'] = _pick_model(state['models'], state['route'], default)


def _step_intent(state, saved):
	_step_header(state, 'Intent model')
	_ensure_models(state)
	# Enter keeps the saved intent model on the same provider, else follows the main model.
	default = state['model']
	if _same_target(state, saved) and saved['intent'] and not _same_model(state['model'], saved['intent']):
		default = next((m for m in state['models'] if _same_model(m, saved['intent'])), saved['intent'])
	# Right after the model step its table is still on screen: its numbers stay valid.
	state['intent'], state['shown'] = _pick_model(
		state['models'], state['route'], default, 'Intent model', shown=state.get('shown'))


def _step_switch_profile(state, saved):
	"""Make another AI profile the active one (``addons.ai.profile``)."""
	_step_header(state, 'Switch profile')
	names = list(dict.fromkeys([DEFAULT_PROFILE, *CONFIG.addons.ai.profiles]))
	labels = [f"{n} · {resolve_ai_profile(n)['model'] or 'no model'}" for n in names]
	name = names[_choose('Use which profile?', labels, default=names.index(saved['profile']))]
	if name == saved['profile']:
		console.print("\n  [green]✓ Nothing changed.[/]")
		return None
	CONFIG.set('addons.ai.profile', '' if name == DEFAULT_PROFILE else name)
	if not CONFIG.validate():
		console.print("  [red]The config did not validate: nothing saved.[/]")
		return None
	CONFIG.save()
	_print_panel(f'✓ Now using profile {escape(name)}', _settings_rows(_saved_setup(name)), style='green')
	return resolve_ai_profile(name)['model']


def _ask_profile(state, saved):
	"""The profile to save to: Enter keeps the one the setup started from, a new name adds one."""
	default = None if state.get('add_profile') else saved['profile']
	while True:
		name = _ask('Save as profile', default=default, help=(
			f"Enter keeps {default}; a new name saves a profile to switch to later." if default else
			'Name the new profile, e.g. fast or local.'))
		if re.fullmatch(r'[\w-]+', name):
			return name
		console.print("  [yellow]Type a name: letters, digits, - or _.[/]")


def _profile_key(profile, field):
	"""The config key of a profile field, and its saved value."""
	ai = CONFIG.addons.ai
	if profile == DEFAULT_PROFILE:
		return f'addons.ai.{_PROFILE_FIELDS[field]}', ai[_PROFILE_FIELDS[field]] or ''
	return f'addons.ai.profiles.{profile}.{field}', (ai.profiles.get(profile) or {}).get(field)


def _step_save(state, saved):
	"""Pick the profile, verify what changed, then save it; on failure the saved setup is kept."""
	import litellm
	target = _ask_profile(state, saved)
	same_profile = target == saved['profile']
	cred = state['cred']
	oauth2 = cred['method'] == 'oauth2'
	# OAuth2 keeps the target's saved API key until the user confirms its removal below.
	values = {key: cred[field] for field, key in _CRED_KEYS.items()}
	saved_key = saved['cred']['api_key'] if same_profile else (_profile_key(target, 'api_key')[1] or '')
	values.update(api_base=state['base'], api_key=saved_key if oauth2 else cred['api_key'])
	current = resolve_ai_profile(saved['profile'])
	auth_changed = not same_profile or cred['method'] != saved['cred']['method'] or any(
		values[k] != current[k] for k in ('api_base', *_CRED_KEYS.values()))
	same = _same_target(state, saved)
	model = saved['model'] if same and _same_model(state['model'], saved['model']) else state['model']
	intent = saved['intent'] if same and _same_model(state['intent'], saved['intent']) else state['intent']
	roles = ((model, saved['model']), (intent, saved['intent']))
	checks = list(dict.fromkeys(new for new, old in roles if new and (auth_changed or new != old)))
	if not checks:
		console.print("\n  [green]✓ Nothing changed.[/]")
		return None
	console.print()
	failed, back_to = [], None
	state['token'] = None  # a fresh OAuth2 token: the one from listing may have expired meanwhile
	try:
		token = _bearer(state)
	except Exception as e:  # noqa: BLE001 - explained to the user, who decides
		console.print(f"  [red]✗ {_explain_error(e, state, cred['client_secret'])}[/]")
		failed, back_to = checks, _step_auth
	for m in checks if not failed else []:
		console.print(f"  [dim]Checking {escape(m)}…[/]")
		try:
			with console.capture():  # call_llm's own retry / auth logs would bury the result
				call_llm([{"role": "user", "content": "Reply with only: OK"}], m, temperature=0,
				         api_base=state['base'], api_key=token)
			console.print(f"  [green]✓ {escape(m)} replied.[/]")
		except Exception as e:  # noqa: BLE001 - explained to the user, who decides
			failed.append(m)
			back_to = back_to or (_step_model if m == model else _step_intent)
			console.print(f"  [red]✗ {escape(m)}: {_explain_error(e, state, token, cred['client_secret'])}[/]")
		finally:
			litellm.api_key = None  # the setup token / key must not linger in the process
	if failed:
		console.print("  [yellow]Your saved setup is unchanged.[/]")
		if _yes('Pick something else?', default=True):
			raise _Back(back_to)
		# OAuth2 settings are saved only once they worked: no "Save anyway" for them.
		if (oauth2 and auth_changed) or not _yes('Save anyway?', default=False):
			return None
	values.update(model=model, intent_model=intent)
	if oauth2 and target == DEFAULT_PROFILE and os.environ.get('SECATOR_ADDONS_AI_API_KEY'):
		console.print("  [yellow]SECATOR_ADDONS_AI_API_KEY is set and overrides the config: unset it to use OAuth2.[/]")
	if oauth2 and auth_changed and values['api_key']:
		# Declined: nothing is saved. The key would win at runtime while the checks above used OAuth2,
		# and on a new base the old endpoint's key must never be saved with it.
		if not _yes('Remove the saved API key? OAuth2 is only used without one.', default=True):
			console.print("  [yellow]Nothing saved: the saved API key would still be used instead of OAuth2.[/]")
			return None
		values['api_key'] = ''
	# Same profile: write what changed (a field it inherits stays inherited). Another one: write it whole.
	# A profile off the addons.ai endpoint inherits no credentials nor intent model: those are written too.
	top = resolve_ai_profile(DEFAULT_PROFILE)
	moved = target != DEFAULT_PROFILE and any(
		values[k].rstrip('/') != top[k].rstrip('/') for k in ('api_base', 'oauth2_endpoint'))
	for field, value in values.items():
		key, saved_value = _profile_key(target, field)
		inherits = same_profile and not (moved and field in (*_ENDPOINT_FIELDS, 'intent_model'))
		if value != (current[field] if inherits else saved_value):
			CONFIG.set(key, value)
	if target != (CONFIG.addons.ai.profile or DEFAULT_PROFILE):
		CONFIG.set('addons.ai.profile', '' if target == DEFAULT_PROFILE else target)
	if not CONFIG.validate():
		console.print("  [red]The config did not validate: nothing saved.[/]")
		return None
	CONFIG.save()
	rows = _settings_rows({**state, 'model': model, 'intent': intent, 'profile': target})
	if failed:
		rows.append(('Checked', '[red]✗ failed[/]'))
		_print_panel('Saved without a successful check', rows, style='yellow')
	else:
		rows.append(('Checked', '[green]✓ ' + ', '.join(escape(c) for c in checks) + '[/]'))
		_print_panel('✓ AI setup saved', rows, style='green')
	if '_path' in CONFIG:
		console.print(f"  [dim]Saved to {escape(str(CONFIG._path))}[/]")
	return model


def setup_ai():
	"""Entry point for ``ai setup``: ``q``, Ctrl+C and EOF leave cleanly, saving nothing."""
	try:
		return _setup_ai_interactive()
	except (_Quit, KeyboardInterrupt, EOFError):
		console.print("\n  [yellow]Setup cancelled: nothing saved.[/]")
		return None


def _saved_setup(profile=None):
	"""The saved AI setup of AI profile ``profile`` (None = the active one), as the wizard state it starts from."""
	import litellm
	try:
		ai = resolve_ai_profile(profile)
	except ValueError as e:
		console.print(f"  [yellow]{escape(str(e))} Starting from the {DEFAULT_PROFILE} profile.[/]")
		ai = resolve_ai_profile(DEFAULT_PROFILE)
	model = ai['model']
	try:
		route = litellm.get_llm_provider(model)[1] if model else ''
	except Exception:  # noqa: BLE001 - unknown model: no saved provider to match
		route = model.split('/')[0] if '/' in model else ''
	saved = {'profile': ai['name'], 'model': model, 'intent': ai['intent_model'], 'route': route,
	         'base': ai['api_base'].rstrip('/')}
	# Same precedence as the runtime: a saved API key wins over OAuth2 settings.
	cred = _blank_cred('oauth2' if ai['oauth2_client_id'] and not ai['api_key'] else 'key')
	cred.update({field: ai[key] for field, key in _CRED_KEYS.items()})
	entry = _saved_entry(_provider_entries(), saved)
	provider = _entry_state(entry, saved['base']) if entry else _entry_state(('lite', route, pretty_provider(route)))
	# The provider entry's route wins (e.g. a registry `openrouter` route over an older `openai/` id),
	# so new picks get it; the saved model id itself is kept until the user picks another one.
	saved['route'] = provider['route']
	return {**saved, **provider, 'cred': cred}


def _setup_ai_interactive():
	"""Walk the setup steps. A first run goes through every step; a re-run starts from the saved
	setup and asks what to change ("Change model" by default).

	A known provider lists its models live from its own API when LiteLLM can, else from
	LiteLLM's bundled list; a gateway or custom base lists ``<base>/models``. ``b`` at any
	prompt goes back one step. Returns the saved model, or ``None`` when nothing was saved.
	"""
	from secator.config import AiAddon
	saved = _saved_setup()
	cred = saved['cred']
	# Anything set beyond the defaults (env-var keys included: a model was picked) is a re-run.
	first_run = not (saved['base'] or cred['api_key'] or cred['client_id'] or CONFIG.addons.ai.profiles
	                 or saved['model'] not in ('', AiAddon.model_fields['default_model'].default))
	if first_run:
		console.print("\n  [bold cyan]AI setup[/] [dim]· pick a provider, sign in, choose a model.[/]")
		plan = [_step_provider, _step_auth, _step_model, _step_intent, _step_save]
	else:
		plan = [_step_menu]
	state, i = {}, 0
	while True:
		if i == 0:
			state = {**saved, 'cred': dict(cred)}
		state['step'] = (i if plan[0] is _step_menu else i + 1, len(plan) - (plan[0] is _step_menu) - 1)
		try:
			result = plan[i](state, saved)
		except _Back as back:
			# Back one step, or to the step named by the save step (e.g. the model that failed).
			target = back.args[0] if back.args else None
			if target and target not in plan:  # e.g. a rejected OAuth2 secret during a model-only re-run
				plan.insert(1, target)
			i = plan.index(target) if target in plan else max(i - 1, 0)
			continue
		if plan[i] is _step_menu:
			if not result:
				console.print("\n  [green]✓ Nothing changed.[/]")
				return None
			plan = [_step_menu] + result
		elif i == len(plan) - 1:
			return result
		i += 1


def prompt_user(history, max_iterations=10, choices=None,
				mode="chat", model=None):
	"""Prompt user for follow-up input via interactive menu.

	Builds a unified menu with optional LLM-provided choices, plus Continue,
	Summarize, and Exit. Does NOT mutate history — the caller is responsible
	for adding the returned answer to history.

	Args:
		history: ChatHistory instance (read-only, used for token counts and compaction).
		max_iterations: Current max iterations (used for continue message).
		choices: Optional list of choice strings from the LLM's stop action.
		model: Optional LLM model name for token count display.

	Returns:
		dict: {"answer": str, "extra_iters": int, "switch_mode": str|None}
		None: to exit.
	"""
	from secator.definitions import IN_WORKER
	if IN_WORKER:
		return None
	from secator.rich import InteractiveMenu
	from secator.ai.prompts import format_continue

	# Build title with token recap
	title = "What's next?"
	if model:
		try:
			from secator.ai.history import get_context_window
			by_role = history.count_tokens_by_role(model)
			ctx_window = get_context_window(model)
			token_str, ctx_str, role_str = _format_token_breakdown(by_role['total'], ctx_window, by_role)
			title += f" [gray42]• {token_str}/[dim red]{ctx_str}[/] ({role_str})[/]"
		except Exception:
			pass

	try:
		options = []

		# Insert LLM-provided choices first (selectable for multi-select via Space)
		if choices:
			for choice in choices:
				options.append({
					"label": choice,
					"input": True,
					"action": "choice",
					"selectable": True,
				})

			# Add "All of the above" when 2+ choices
			if len(choices) >= 2:
				options.append({
					"label": "All of the above",
					"input": True,
					"action": "all_choices",
				})

		# Default options (always present)
		continue_label = f"Continue to {mode}"
		default_options = [
			{"label": continue_label, "input": True, "action": "continue"},
			{"label": "Summarize", "input": True, "action": "summarize", "default": "Summarize all findings so far"},
		]

		# Add "Compact context" when context is >50% full
		if model:
			try:
				from secator.ai.history import get_context_window, OUTPUT_TOKEN_RESERVATION
				by_role = history.count_tokens_by_role(model)
				ctx_window = get_context_window(model)
				usable = ctx_window - OUTPUT_TOKEN_RESERVATION
				pct_used = (by_role["total"] / usable * 100) if usable > 0 else 0
				if pct_used >= 25:
					default_options.append({"label": f"Compact context ({pct_used:.0f}% full)", "action": "compact"})
			except Exception:
				pass

		default_options.append({"label": "Exit", "action": "exit"})
		options.extend(default_options)

		result = InteractiveMenu(title, options).show()
		if result is None:
			return None

		idx_or_indices, value = result

		# Multi-select: Space-toggled multiple choices
		if isinstance(idx_or_indices, list):
			selected_choices = [options[i]["label"] for i in idx_or_indices if options[i].get("selectable")]
			if selected_choices:
				numbered = [f"{i}) {c}" for i, c in enumerate(selected_choices, 1)]
				msg = f"Do all of the following: {', '.join(numbered)}"
				if value:
					msg += f". Additional instructions: {value}"
				return {"answer": msg, "extra_iters": max_iterations}

		idx = idx_or_indices
		action = options[idx].get("action")

		if action == "continue":
			msg = value if value else format_continue(0, max_iterations)
			return {"answer": msg, "extra_iters": max_iterations}

		if action == "summarize":
			summary_msg = value if value else "Summarize all findings so far and provide a final report."
			return {"answer": summary_msg, "extra_iters": 1, "switch_mode": "chat"}

		if action == "choice":
			choice_label = options[idx].get("label", "")
			msg = choice_label
			if value:
				msg = f"{choice_label}: {value}"
			return {"answer": msg, "extra_iters": 1}

		if action == "all_choices":
			numbered = [f"{i}) {c}" for i, c in enumerate(choices, 1)]
			msg = f"Do all of the following: {', '.join(numbered)}"
			if value:
				msg += f". Additional instructions: {value}"
			return {"answer": msg, "extra_iters": max_iterations}

		if action == "compact":
			old_tokens = history.count_tokens(model)
			history.compact(model)
			new_tokens = history.count_tokens(model)
			console.print(f"[bold green]Compacted context: {old_tokens} -> {new_tokens} tokens[/]")
			return prompt_user(history, max_iterations, choices, mode, model)

		# exit
		return None
	except (KeyboardInterrupt, EOFError):
		return None
