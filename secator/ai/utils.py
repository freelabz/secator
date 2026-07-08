# secator/ai/utils.py
"""Utility functions for AI task - LLM initialization, calling, and response parsing."""
import json
import logging
import os
import random
from dataclasses import fields
from typing import Any, Dict, List, Optional

from secator.definitions import LLM_SPINNER_MESSAGES
from secator.config import CONFIG
from secator.output_types import Warning, Error
from secator.rich import console, maybe_status
from secator.runners import Task
from secator.utils import format_token_count

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
	return {k: v for k, v in os.environ.items()
			if not any(k.startswith(p) for p in SENSITIVE_ENV_PREFIXES)
			and "KEY" not in k and "SECRET" not in k and "TOKEN" not in k and "PASSWORD" not in k}


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


_HEAVY_PROFILES = {'large', 'extra_large'}


def _is_heavy_runner(runner_type: str, name: str, opts: dict = None) -> bool:
	"""Whether a sub-runner is too heavy to run sync in-process inside the ai worker.

	Workflows/scans fan out across multiple pools, so they should always be
	dispatched rather than run in-process. A task is heavy if its (possibly
	opts-dependent) profile maps to a large worker pool (``large``/``extra_large``).
	"""
	if runner_type != 'task':
		return True
	try:
		cls = Task.get_task_class(name)
	except Exception:
		return False
	profile = getattr(cls, 'profile', 'small')
	if callable(profile):
		try:
			profile = profile(opts or {})  # resolve dynamic profile (mirrors Command.s/si)
		except Exception:
			return True  # can't resolve — be conservative and dispatch
	return profile in _HEAVY_PROFILES


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
})

# Cap a spawned subagent's iteration budget so it can't be told to loop unbounded.
_MAX_CHILD_ITERATIONS = 25


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
		f"## Expected output\nInvestigate the objective, then report your findings concisely. "
		f"Persist any new findings; do not repeat work already listed under 'Already known'."
	)


def _union_live_results(persisted: List[Dict], live_results: List[Dict], query_filter: Dict, limit: int) -> List[Dict]:
	"""Union backend results with this run's in-memory findings (local driver only).

	The live findings are filtered by the SAME query via an in-memory json backend,
	then merged into the backend (disk) results and deduped by ``_uuid`` (backend wins),
	respecting ``limit``. Makes query_workspace the single source of truth under the
	local driver, whose JSON exporter only writes to disk at end-of-run.
	"""
	if not live_results:
		return persisted
	from secator.query import QueryEngine
	# workspace_id "" + a `results` context => an in-memory json backend that filters
	# the provided results by the query (no disk access).
	live = QueryEngine("", context={"results": live_results}).search(query_filter, limit=limit or 0)
	seen = {r.get("_uuid") for r in persisted if r.get("_uuid")}
	for r in live:
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
			'str': str, 'list': list, 'dict': dict,
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


def _repair_orphan_tool_uses(messages: List[Dict]) -> int:
	"""Repair orphan tool_use/tool_result pairing for Anthropic/OpenAI.

	Two defects are fixed (both mutate `messages` in place):
	- LEADING orphan tool_results: a kept window starting with a tool_result
	  whose assistant(tool_calls) parent was trimmed away (see
	  `_strip_leading_orphan_tools`).
	- FORWARD orphan tool_uses: an assistant tool_use block not immediately
	  followed by a matching tool_result (synthesize an acknowledged result).

	Args:
		messages: List of message dicts in litellm/OpenAI format.

	Returns:
		Number of messages removed or synthetic tool_results inserted.
	"""
	# Leading orphan tool_results have no parent in this window — drop them.
	repaired = _strip_leading_orphan_tools(messages)
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
			fn = tc.get("function", {}) if isinstance(tc, dict) else getattr(tc, "function", None)
			if isinstance(fn, dict):
				name = fn.get("name", "")
			else:
				name = getattr(fn, "name", "") if fn else ""
			to_insert.append({
				"role": "tool",
				"tool_call_id": tc_id,
				"name": name,
				"content": '{"status":"acknowledged"}',
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

	# Set API key if provided (can be called multiple times)
	if api_key:
		litellm.api_key = api_key

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
			if "litellm" not in CONFIG.debug:
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
		fn = tc.get("function", {}) if isinstance(tc, dict) else getattr(tc, "function", None)
		if isinstance(fn, dict):
			name, args = fn.get("name", ""), fn.get("arguments", "")
		elif fn is not None:
			name, args = getattr(fn, "name", ""), getattr(fn, "arguments", "")
		else:
			name, args = "", ""
		completion_text += f" {name} {args}"
	completion_tokens = _count(text=completion_text)
	return {
		"tokens": prompt_tokens + completion_tokens,
		"prompt_tokens": prompt_tokens,
		"completion_tokens": completion_tokens,
		"cost": None,
	}


def call_llm(
	messages: List[Dict],
	model: str,
	temperature: float = 0.7,
	api_base: Optional[str] = None,
	api_key: Optional[str] = None,
	max_retries: int = 3,
	tools: Optional[List[Dict]] = None,
) -> Dict:
	"""Call litellm completion and return response with usage."""
	import time
	import litellm

	# Initialize litellm once (avoids callback accumulation)
	init_llm(api_key=api_key)

	kwargs = dict(
		model=model,
		messages=messages,
		temperature=temperature,
		api_base=api_base,
	)
	# HARD DEBUG (ALL COMPLETE MESSAGES EXCEPT SYSPROMPT)
	# Remove only when we have a better way to show this
	if tools is not None:
		kwargs["tools"] = tools
		kwargs["tool_choice"] = "auto"

	# Normalize assistant messages that have tool_calls but no 'content' key.
	# litellm's trim_messages crashes with KeyError: 'content' on such messages.
	for msg in kwargs["messages"]:
		if msg.get("role") == "assistant" and "content" not in msg:
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
		try:
			response = litellm.completion(**kwargs)
			break
		except litellm.BadRequestError as e:
			# 400s fail fast, except the orphan tool_use case which we repair
			# and retry (not counted as an attempt — the repair is the real fix).
			err_str = str(e)
			if 'tool_use' in err_str and 'tool_result' in err_str:
				repaired = _repair_orphan_tool_uses(kwargs["messages"])
				if repaired:
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
			console.print(Error(message=e))
			console.print(Error(
				message='Please set a valid API key with `secator config set addons.ai.api_key <KEY>`'
			))
			raise

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

	return {"content": content, "usage": usage, "tool_calls": tool_calls}


MODEL_COLORS = [
	'cyan', 'green', 'yellow', 'magenta', 'red', 'blue',
	'bright_cyan', 'bright_green', 'bright_yellow', 'bright_magenta',
	'bright_red', 'bright_blue', 'orange3', 'deep_pink2', 'dark_olive_green3',
	'medium_purple3', 'dodger_blue2', 'gold3', 'spring_green3', 'hot_pink',
]


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


def setup_ai():
	"""Interactive search-filter-select flow for configuring AI model and API key."""
	import litellm
	from rich.prompt import Prompt

	# Load all models, sort, build color map
	all_models = []
	all_parts = set()
	for provider, model_names in litellm.models_by_provider.items():
		model_names = sorted(model_names)
		for name in model_names:
			parts = name.split('/')
			if parts[0] != provider:
				parts = [provider] + parts
			all_models.append('/'.join(parts))
			for p in parts[:-1]:
				all_parts.add(p)
	part_colors = {p: MODEL_COLORS[i % len(MODEL_COLORS)] for i, p in enumerate(sorted(all_parts))}

	def _format_model(m, idx=None):
		parts = m.split('/')
		if len(parts) > 1:
			segments = [f"[bold {part_colors[p]}]{p}[/]" for p in parts[:-1]]
			colored = '/'.join(segments) + f"/[bold white]{parts[-1]}[/]"
		else:
			colored = f"[bold white]{m}[/]"
		prefix = f"[dim]{idx:>4}[/] " if idx is not None else "  "
		return prefix + colored

	# Show current config
	current_model = CONFIG.addons.ai.default_model
	current_intent = CONFIG.addons.ai.intent_model
	current_key = CONFIG.addons.ai.api_key
	masked_key = f"{current_key[:8]}...{current_key[-4:]}" if current_key and len(current_key) > 12 else current_key or ""
	console.print()
	console.print("[bold]  Current config:[/]")
	console.print(f"    Model:        [bold white]{current_model or 'not set'}[/]")
	console.print(f"    Intent model: [bold white]{current_intent or 'not set'}[/]")
	console.print(f"    API key:      [bold white]{masked_key or 'not set'}[/]")
	console.print()

	# Display all models numbered
	displayed = all_models
	suffix = ''
	console.print(f"[bold]  Found {len(displayed)} models{suffix}:[/]")
	for i, m in enumerate(displayed, 1):
		console.print(_format_model(m, idx=i), highlight=False)

	# Enter prompt loop
	while True:
		console.print()
		choice = Prompt.ask("[bold cyan]  Filter or select (number/name, q to quit)[/]")

		if not choice:
			# Empty input: re-show current list
			console.print(f"\n[bold]  Found {len(displayed)} models{suffix}:[/]")
			for i, m in enumerate(displayed, 1):
				console.print(_format_model(m, idx=i), highlight=False)
			continue

		if choice.lower() in ('q', 'quit', 'exit'):
			return None

		# Number → select from current display
		if choice.isdigit():
			idx = int(choice)
			if 1 <= idx <= len(displayed):
				selected = displayed[idx - 1]
			else:
				console.print(f"[bold red]  Invalid number: {idx} (valid: 1-{len(displayed)})[/]")
				continue
		else:
			# Check exact match first
			exact = [m for m in all_models if m.lower() == choice.lower()]
			if exact:
				selected = exact[0]
			else:
				# Text → filter models, re-display
				query_lower = choice.lower()
				filtered = [m for m in all_models if query_lower in m.lower()]
				if not filtered:
					console.print(f'[bold yellow]  No models matching "{choice}".[/]')
					continue
				if len(filtered) == 1:
					selected = filtered[0]
				else:
					displayed = filtered
					suffix = f' matching "{choice}"'
					console.print(f"\n[bold]  Found {len(displayed)} models{suffix}:[/]")
					for i, m in enumerate(displayed, 1):
						console.print(_format_model(m, idx=i), highlight=False)
					continue

		# Model selected - save config
		console.print(f"\n[bold green]  Selected: [white]{selected}[/][/]")
		CONFIG.set('addons.ai.default_model', selected)
		CONFIG.set('addons.ai.intent_model', selected)

		# Prompt for API key if model changed or key unset
		api_key = Prompt.ask(
			"  [bold cyan]API key[/] [dim](leave empty to keep current)[/]",
			default=masked_key,
			show_default=bool(masked_key),
		)
		if api_key and api_key != masked_key:
			CONFIG.set('addons.ai.api_key', api_key)

		config = CONFIG.validate()
		if config:
			CONFIG.save()
			console.print(f"[bold green]  Default model set to [white]{selected}[/][/]")
			console.print(f"[bold green]  Intent model set to [white]{selected}[/][/]")
		else:
			console.print(f"[bold yellow]  Model selected: {selected} (config validation failed, not saved)[/]")

		# Verify with a simple LLM call
		api_key = CONFIG.addons.ai.api_key
		api_base = CONFIG.addons.ai.api_base
		console.print()
		try:
			with maybe_status("[bold orange3]Verifying model connection...[/]", spinner="dots"):
				result = call_llm(
					[{"role": "user", "content": "Reply with only: OK"}],
					selected, temperature=0, api_base=api_base, api_key=api_key,
				)
			console.print(f"[bold green]  Connection verified! Response: {result['content'].strip()}[/]")
		except Exception as e:
			console.print(f"[bold red]  Connection failed: {e}[/]")
			console.print("[dim]  Check your API key and model name.[/]")

		return selected


def prompt_user(history, encryptor=None, max_iterations=10, choices=None,
				mode="chat", model=None):
	"""Prompt user for follow-up input via interactive menu.

	Builds a unified menu with optional LLM-provided choices, plus Continue,
	Summarize, and Exit. Does NOT mutate history — the caller is responsible
	for adding the returned answer to history.

	Args:
		history: ChatHistory instance (read-only, used for token counts and compaction).
		encryptor: Optional SensitiveDataEncryptor (unused, kept for compat).
		max_iterations: Current max iterations (used for continue message).
		choices: Optional list of choice strings from LLM follow_up action.
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
					"action": "follow_up",
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

		if action == "follow_up":
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
			return prompt_user(history, encryptor, max_iterations, choices, mode, model)

		# exit
		return None
	except (KeyboardInterrupt, EOFError):
		return None
