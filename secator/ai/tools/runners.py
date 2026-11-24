"""AI tools that launch and list runners.

* ``run_task`` / ``run_workflow`` — run a secator task / workflow.
* ``run_shell`` — run a shell command (optionally in the sandbox container).
* ``run_subagent`` — delegate to a child ``ai`` task.
* ``list_runners`` — list the workspace run history.

The runner execution machinery they share lives in ``_runner.py`` (and ``_sandbox.py``
for ``run_shell``).
"""
from typing import Dict, Generator
from secator.output_types import Error, Ai, Info, Warning
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._runner import _run_runner, resolves_to_ai_task, _child_preamble, _child_run_opts, _record_spawn
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA
from secator.runners import Task
from secator.ai.utils import _denied_secret_read, _sanitized_env, _scrub_secrets, _truncate
from secator.ai.tools._sandbox import _ensure_sandbox_container, _sandbox_container_name, _wrap_docker_exec
from secator.ai.prompts import normalize_mode
from secator.query._base import RUNNER_ORDER_DESC


# ---------- run_task ----------

class RunTask(BaseTool):
	name = "run_task"
	action = "task"
	schema = {
		"type": "function",
		"function": {
			"name": "run_task",
			"description": "Run a secator security task (e.g. nmap, httpx, nuclei) against targets. To spawn an AI subagent use run_subagent (NOT name='ai'). "  # noqa: E501
			               "Example (good): run_task(name='nmap', targets=['10.0.0.1'], opts={'ports':'1-1000'}, description='Scan common ports'). "  # noqa: E501
			               "Bad: run_task(name='nmap') — no targets; run_task() — no args.",
			"parameters": {
				"type": "object",
				"properties": {
					"name": {
						"type": "string",
						"description": "The task name (e.g. nmap, httpx, nuclei, ffuf)."
					},
					"targets": _TARGETS_SCHEMA,
					"description": _DESCRIPTION_SCHEMA,
					"opts": {
						"type": "object",
						"description": "Optional task-specific options (e.g. ports, rate_limit). Control/security flags are ignored."
					}
				},
				"required": ["name", "targets", "description"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Execute a secator task. Spawning an AI subagent goes through run_subagent, not
		run_task(name="ai") — reject the latter with a clear pointer."""
		if resolves_to_ai_task(action.get("name")):
			yield Error(
				message="To spawn an AI subagent, use the run_subagent tool, not run_task(name=\"ai\").",
				_context=_get_result_context(action, ctx),
			)
			return
		yield from _run_runner(action, ctx, "task")


# ---------- run_workflow ----------

class RunWorkflow(BaseTool):
	name = "run_workflow"
	action = "workflow"
	schema = {
		"type": "function",
		"function": {
			"name": "run_workflow",
			"description": "Run a secator workflow (a composed sequence of tasks) against one or more targets.",
			"parameters": {
				"type": "object",
				"properties": {
					"name": {
						"type": "string",
						"description": "The workflow name."
					},
					"targets": _TARGETS_SCHEMA,
					"description": _DESCRIPTION_SCHEMA,
					"opts": {
						"type": "object",
						"description": "Optional workflow options (e.g. profiles). Control/security flags are ignored."
					}
				},
				"required": ["name", "targets", "description"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Execute a secator workflow."""
		yield from _run_runner(action, ctx, "workflow")


# ---------- run_shell ----------

# Cap shell stdout before it enters AI history so a huge command can't blow up
# the next prompt's token budget; head+tail keeps both the start and the result.
_MAX_SHELL_OUTPUT_CHARS = 4000


# Fallback default timeout (seconds) for ad-hoc AI shell commands when no config is
# available. The real default is CONFIG.security.shell_default_timeout (30s); see
# _resolve_shell_timeout. Applied as an instance attribute post-construction (see
# RunShell.run) since max_timeout is not a run_opts-settable field.
_SHELL_TIMEOUT = 30


def _resolve_shell_timeout(action: Dict) -> int:
	"""Effective max_timeout (seconds) for a single AI shell command.

	Settable range is ``[default, ceiling]``:
	- ``default = CONFIG.security.shell_default_timeout`` (30s) — the per-command default so an
	  interactive user doesn't wait forever when the model runs a command;
	- ``ceiling = CONFIG.celery.task_max_timeout`` — the SAME global max-task-timeout cap every
	  task honors (``-1`` = no cap), so a long command can still complete where the operator
	  allows long tasks, but the model can't exceed that bound.

	The model passes ``timeout`` on run_shell to raise a slow command toward the ceiling (and
	re-run after a timeout). A value below the default is floored to it; above the ceiling is
	capped. Absent/non-numeric falls back to the default. run_shell-only; other runners resolve
	their timeout through the normal config path, unchanged.
	"""
	from secator.config import CONFIG
	default = getattr(getattr(CONFIG, "security", None), "shell_default_timeout", _SHELL_TIMEOUT) or _SHELL_TIMEOUT
	requested = action.get("timeout")
	base = default
	if requested is not None:
		try:
			base = int(requested)
		except (TypeError, ValueError):
			base = default
	base = max(base, default)  # floor: never below the per-command default
	ceiling = CONFIG.celery.task_max_timeout
	if ceiling is not None and ceiling > 0:
		base = min(base, ceiling)  # cap: never above the global task-timeout ceiling
	return base


class RunShell(BaseTool):
	name = "run_shell"
	action = "shell"
	schema = {
		"type": "function",
		"function": {
			"name": "run_shell",
			"description": "Run an arbitrary shell command for exploration, exploitation, or data analysis. "
			               "Commands default to a 30s timeout; if one times out and just needs longer (a slow "
			               "install, a long scan), re-run it with a higher `timeout`. "
			               "Example (good): run_shell(command='curl -sk https://10.0.0.1/ | head -50', description='Grab the HTTP banner'). "  # noqa: E501
			               "Bad: run_shell() — no command.",
			"parameters": {
				"type": "object",
				"properties": {
					"command": {
						"type": "string",
						"description": "The shell command to execute."
					},
					"timeout": {
						"type": "integer",
						"description": "Optional max run time in seconds for THIS command (default 30). Raise it for a "
						               "slow command (install, long scan) and re-run after a timeout. Capped at the "
						               "server's configured maximum task timeout; values below the default are floored."  # noqa: E501
					},
					"description": _DESCRIPTION_SCHEMA
				},
				"required": ["command", "description"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Execute a shell command as a `command` task runner.

		Dispatches the built-in `command` task (a Command subclass that runs an arbitrary
		shell command line verbatim) through the normal runner lifecycle, instead of a raw
		`subprocess.run`. This makes the shell invocation persist as a runner doc (via the
		driver hooks rebuilt from `context['drivers']`) and appear in history, parented
		under the conversation via `context['session_id']` — exactly like `_run_runner`
		does for AI-spawned tasks/workflows.

		Args:
			action: Action dict with command
			ctx: Action context
		"""
		command = action.get("command", "")
		context = _get_result_context(action, ctx)

		if ctx.encryptor:
			command = ctx.encryptor.decrypt(command)

		# Unconditional secret-source deny (holds even when dangerous=True disables the
		# permission engine): never let the AI read secator's config/.env or /proc environ.
		# Skipped when --isolated: the command runs in the container, which has none of the
		# worker's config/.env/secrets, so the deny is moot (and would over-block in-container reads).
		if not ctx.isolated:
			secret_denial = _denied_secret_read(command)
			if secret_denial:
				yield Ai(content=command, ai_type="shell", _context=context)
				yield Ai(content=f"[denied] {secret_denial}", ai_type="shell_output", _context=context)
				return

		if ctx.dry_run:
			where = f" (in sandbox {_sandbox_container_name(ctx, context)})" if ctx.isolated else ""
			yield Info(message=f"[DRY RUN]{where} Would run: {command}", _context=context)
			return

		# --isolated: run the command inside a per-runner Kali container via `docker exec`. The Ai
		# transcript still shows the ORIGINAL command; only what CommandTask executes is wrapped.
		exec_command = command
		if ctx.isolated:
			try:
				exec_command = _wrap_docker_exec(_ensure_sandbox_container(ctx, context), command)
			except Exception as e:
				yield Ai(content=command, ai_type="shell", _context=context)
				yield Ai(content=f"[sandbox error] could not start isolation container: {e}",
				         ai_type="shell_output", _context=context)
				return

		try:
			# Don't silently run a persistence-less child when the parent has drivers
			# (same guard _run_runner uses for spawned tasks/workflows).
			hooks, denial = _child_preamble(ctx, context)
			if denial is not None:
				yield denial
				return

			# hooks is CLASS-keyed ({Task: {...}}); we bypass the Task wrapper with a direct
			# `command(...)` instantiation, so extract hooks[Task] ourselves — else register_hooks
			# finds no match and the runner doc is silently never persisted (no error, no doc).
			hooks = hooks.get(Task, {})

			# Mirrors _run_runner's wiring: quiet, reports enabled, never dangerous (defense
			# in depth). `env` is the sanitized process env so `env`/`printenv` can't leak secrets.
			run_opts = {
				**_child_run_opts(ctx),
				"print_cmd": False,
				"dangerous": False,
				"env": _sanitized_env(),
				# Never let an AI-issued command block the loop on an interactive prompt. tty=False
				# makes Command._prompt_sudo take its non-interactive path: a sudo command with no
				# passwordless/configured sudo fails fast with an actionable error instead of
				# hanging on getpass (the stall in a --dangerous, non-isolated TTY session). The
				# session_context block already tells the model whether sudo is usable.
				"tty": False,
			}
			# Human-readable description the LLM supplied (shown by clients instead of the
			# bare "command" name). See _run_runner for the run_opts['description'] mapping.
			if action.get("description"):
				run_opts["description"] = action["description"]

			# Instantiate `command` directly (bypasses the Task wrapper, which discards `.output`)
			# so stdout survives while persist hooks still fire. Spread **run_opts, not `run_opts=`
			# (would nest and drop `env`); import locally to avoid a circular import.
			from secator.tasks.command import command as CommandTask
			runner = CommandTask([exec_command], hooks=hooks, context=context, **run_opts)
			_record_spawn(ctx, runner, context.get("task_chunk_id"), context.get("task_id"))

			# Per-command timeout. max_timeout is NOT run_opts-settable (Command.__init__ resolves
			# it from CONFIG.tasks.overrides); setting the instance attribute here is honored by
			# get_max_timeout(). Defaults to CONFIG.security.shell_default_timeout (30s); the model
			# can raise it via run_shell(timeout=...), bounded by CONFIG.celery.task_max_timeout.
			effective_timeout = _resolve_shell_timeout(action)
			runner.max_timeout = effective_timeout
			# Check the timeout at least once a second: the default monitor cadence is
			# stat_update_frequency (tens of seconds), which would let a short shell timeout
			# lapse unenforced. Stats stay gated to their own frequency (no extra overhead).
			runner.monitor_poll_interval = min(1.0, effective_timeout)

			# Emit the command Ai now that the runner exists: its on_init hook has
			# stamped the runner id into context, so clients can link this item to the
			# persisted runner doc (mirrors _run_runner:688-699).
			yield Ai(
				content=command,
				ai_type="shell",
				extra_data={
					# Chunk doc `_id` is keyed on task_chunk_id (task_id now points at the
					# parent ai task for grouping). See _run_runner for the same ordering.
					"runner_id": context.get("task_chunk_id") or context.get("task_id", "") or runner.id,
					"runner_type": "task",
					# LLM-supplied human-readable description, rendered in the AI chat row.
					"description": action.get("description", ""),
				},
				_context=context,
			)

			# Run to completion in-process (fires persist hooks like a normal task/workflow).
			# Do NOT `yield from runner` — raw stdout lines aren't separate transcript items;
			# the single shell_output below is the contract.
			runner.run()

			# Scrub secrets BEFORE truncating (a secret in the middle would survive if we
			# truncated first), then cap so it can't blow up history.
			output = _truncate(_scrub_secrets(runner.output or "(no output)"), _MAX_SHELL_OUTPUT_CHARS)
			# On timeout, tell the model it can re-run with a higher `timeout` (and the cap), so it
			# retries deliberately instead of giving up or blindly re-running the same command.
			# `is True` (not just truthy): the real runner always sets a bool, and this avoids a
			# test MagicMock's auto-created attribute reading as "timed out".
			if getattr(runner, "timed_out", False) is True:
				from secator.config import CONFIG
				ceiling = CONFIG.celery.task_max_timeout
				cap = f" (max {ceiling}s)" if ceiling is not None and ceiling > 0 else ""
				output += (
					f"\n\n[timed out after {effective_timeout}s] If this command just needs longer, "
					f"re-run it with a higher `timeout`{cap}; otherwise change the approach."
				)
			yield Ai(
				content=output,
				ai_type="shell_output",
				# Same runner id as the `shell` item above, so a frontend routes this stdout to
				# the command's OWN panel by id — NOT to whatever panel is "current" (in a parallel
				# batch several actions stream at once, so `current` may be a sibling task's panel).
				extra_data={
					"runner_id": context.get("task_chunk_id") or context.get("task_id", "") or runner.id,
				},
				_context=context,
			)

		except Exception as e:
			yield Error(message=f"Shell command failed: {e}", _context=context)


# ---------- run_subagent ----------

class RunSubagent(BaseTool):
	name = "run_subagent"
	action = "subagent"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "run_subagent",
			"description": (
				"Spawn an autonomous AI subagent with a fresh context window that works the objective "
				"non-interactively, on the same model as you, and hands back a summary — the ONLY way to spawn a subagent (do NOT "
				"use run_task with name='ai'). Use it to parallelize or offload a focused sub-task.\n"
				"Mode: in an AUTO or scan session you MAY set `mode` to pick the subagent's mode "
				"(e.g. hand a confirmed vuln to an `exploit` subagent). In a user-PINNED read-only `chat` "
				"session the subagent is forced to `chat`; do NOT set a different `mode` there.\n"
				"Example (good): run_subagent(objective='Validate and exploit CVE-2021-41773 on "
				"10.0.0.9, record a PoC', targets=['10.0.0.9'], "
				"description='Exploit the Apache path traversal', mode='exploit'). "
				"Bad: run_subagent(objective='do stuff') — no targets, vague objective."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"objective": {
						"type": "string",
						"description": "The subagent's goal, with ALL context it needs (target details, "
						               "relevant findings as raw JSON, credentials/versions). It has a fresh "
						               "context window and sees only what you pass here."
					},
					"targets": _TARGETS_SCHEMA,
					"description": _DESCRIPTION_SCHEMA,
					"mode": {
						"type": "string",
						"enum": ["chat", "scan", "exploit"],
						"description": "Optional mode for the subagent (chat/scan/exploit). Honored only in an "
						               "auto or scan session; ignored/forced to chat in a pinned chat session. "
						               "Omit to inherit the current mode."
					}
				},
				"required": ["objective", "targets", "description"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Spawn an AI subagent (the ONLY subagent entrypoint).

		Mode policy:
		- A user-PINNED read-only ``chat`` session forces the subagent to ``chat``; if the
		  model asks for a different mode, refuse and tell it to have the user switch to
		  ``auto`` (a read-only session must not spawn an acting subagent behind the user).
		- An ``auto`` or ``scan`` session may set the subagent's ``mode`` (e.g. hand a vuln
		  to an ``exploit`` subagent); omitted means inherit the parent's current mode.
		``exploit`` mode isn't given this tool at all (see MODES), so a focused exploit run
		can't fan out."""
		requested_mode = normalize_mode(action.get("mode") or "") or None
		pinned_chat = (not getattr(ctx, "mode_is_auto", True)) and ctx.mode == "chat"
		if pinned_chat:
			if requested_mode and requested_mode != "chat":
				yield Error(
					message=(
						"A subagent cannot be spawned in a different mode than the current 'chat' mode. "
						"Ask the user to change the current mode to 'auto' so the subagent can pick its mode."
					),
					_context=_get_result_context(action, ctx),
				)
				return
			child_mode = "chat"
		else:
			child_mode = requested_mode or ctx.mode or "chat"
		objective = action.get("objective") or action.get("prompt") or ""
		# No `model` here: a subagent always runs on its parent's model (forced in
		# `_run_runner`), so the tool neither exposes nor forwards one.
		opts = {"prompt": objective, "mode": child_mode}
		task_action = {
			"action": "task",
			"name": "ai",
			"targets": action.get("targets", ctx.targets),
			"description": action.get("description", ""),
			"opts": opts,
			"tool_call_id": action.get("tool_call_id"),
			"tool_call_name": action.get("tool_call_name"),
		}
		yield from _run_runner(task_action, ctx, "task")


# ---------- list_runners ----------

class ListRunners(BaseTool):
	name = "list_runners"
	action = "list_runners"
	auto_allow = True  # read-only run-history lookup; no mutation, no target/path egress
	schema = {
		"type": "function",
		"function": {
			"name": "list_runners",
			"description": (
				"List the run history of this workspace — the scans / workflows / tasks that have run, "
				"newest first, with their status, targets and timing. Use it to answer questions like "
				"'which scans ran in the last 24h?' or 'what failed recently?'. This lists RUN activity; "
				"use query_workspace for the findings those runs produced."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"runner_type": {
						"type": "string",
						"enum": ["scan", "workflow", "task"],
						"description": "Filter to one runner type (e.g. 'scan'). Omit to list all types."
					},
					"since": {
						"type": "string",
						"description": "Only runners started within this window: a relative age like '24h', '7d', '30m', '2w', or an ISO-8601 date/datetime. Omit for no time filter."  # noqa: E501
					},
					"status": {
						"type": "string",
						"description": "Filter by run status (e.g. 'SUCCESS', 'FAILURE', 'RUNNING'). Omit for any."
					},
					"include_children": {
						"type": "boolean",
						"description": "Include nested child runners (a scan's sub-workflows/tasks). Default false = top-level runs only."  # noqa: E501
					},
					"limit": {
						"type": "integer",
						"description": "Maximum runners to return (default 50).",
						"default": 50
					}
				},
				"required": []
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""List the workspace's runner run-history (scans/workflows/tasks), newest first.

		Read-only observation tool: reads run metadata (status/targets/timing) via
		``QueryEngine.list_runners`` — it does NOT read findings (use query_workspace for those)
		and touches no targets, so it is auto-allowed like query. Results are surfaced to the
		model only (marked ``ai_query_result``); nothing is persisted.
		"""
		from secator.ai.runner_history import filter_runners
		context = _get_result_context(action, ctx)

		runner_type = action.get("runner_type") or None
		if runner_type:
			runner_type = str(runner_type).strip().lower() or None
		since = action.get("since")
		status = action.get("status")
		limit = action.get("limit", 50)
		# Default to outermost runs only (a scan, not its many sub-tasks); include_children opens it up.
		has_parent = None if action.get("include_children") else False

		workspace_id = ctx.context.get("workspace_id", "")
		engine = ctx.get_query_engine()
		is_local = getattr(engine.backend, "name", "") == "json"
		if not is_local and not workspace_id:
			yield Warning(message="No workspace available to list runners", _context=context)
			return

		try:
			# Most recent first: the output can be truncated (limit, context budget), so the most
			# recent runs, the most useful ones, must lead the response.
			runners = engine.list_runners(
				workspace_id=workspace_id or None, runner_type=runner_type, has_parent=has_parent,
				order=RUNNER_ORDER_DESC)
		except Exception as e:
			yield Error(message=f"Failed to list runners: {e}", _context=context)
			return

		try:
			summaries = filter_runners(runners, since=since, status=status, limit=limit)
		except ValueError as e:
			yield Error(message=str(e), _context=context)
			return
		# Signal truncation so the model can tell "exactly limit" from "more exist".
		try:
			limit_int = int(limit)
		except (TypeError, ValueError):
			limit_int = 50
		has_more = bool(limit_int > 0 and len(summaries) >= limit_int)
		yield Ai(
			content=(f"{runner_type or 'runner'} history"
			         + (f" since {since}" if since else "")
			         + (f" status={status}" if status else "")),
			ai_type="list_runners",
			extra_data={"runners": summaries, "count": len(summaries), "has_more": has_more,
			            "runner_type": runner_type, "since": since, "status": status},
			_context=context,
		)
		if not summaries:
			yield Info(
				message=("No runners found"
				         + (f" of type {runner_type}" if runner_type else "")
				         + (f" since {since}" if since else "")
				         + (f" with status {status}" if status else "") + "."),
				_context=context,
			)
			return
		for row in summaries:
			row = dict(row)
			row.setdefault("_type", "runner")
			row["_context"] = {**context, "ai_query_result": True}
			yield row


# ---------- get_runner / stop_runner ----------

_RUNNER_ID_SCHEMA = {
	"type": "string",
	"description": "The runner id: a run card's / run result's runner_id, or `run_id`/`_id` from list_runners.",
}
_RUNNER_TYPE_SCHEMA = {
	"type": "string",
	"enum": ["task", "workflow", "scan"],
	"description": "The runner type, if known (faster lookup). Omit to search all types.",
}
# Context keys naming the ai task itself or the runners it runs under.
_SELF_ID_KEYS = ("task_id", "task_chunk_id", "workflow_id", "scan_id")


def _runner_lookup(action, ctx):
	"""``(engine, doc, runner_type, workspace_id)`` for the runner an action names; doc is
	None when not found (or the run has no store)."""
	from secator.ai.runner_history import find_runner_doc
	workspace_id = ctx.context.get("workspace_id", "") or None
	try:
		engine = ctx.get_query_engine()
	except Exception:  # noqa: BLE001 - no store: nothing to look up
		return None, None, None, workspace_id
	doc, rtype = find_runner_doc(engine, action.get("runner_id"), action.get("runner_type"), workspace_id)
	return engine, doc, rtype, workspace_id


def _stop_live_runner(runner):
	"""Stop a runner object held by this process through the paths that actually end it:
	the Celery revoke of its tasks when it runs asynchronously (``Runner.stop_celery_tasks``),
	else a SIGTERM to its running command process. Returns ``(how, revoked_ids)``; ``how`` is
	"" when neither applies (e.g. an in-process workflow between commands): nothing stopped."""
	import signal
	if not getattr(runner, "sync", True) and getattr(runner, "celery_ids_map", None):
		revoked = list(runner.celery_ids_map)
		runner.stop_celery_tasks()
		return "revoked its Celery tasks", revoked
	if getattr(runner, "process", None) is not None and callable(getattr(runner, "stop_process", None)):
		runner.stop_process(exit_ok=True, sig=signal.SIGTERM)
		return "killed its running command", []
	return "", []


class GetRunner(BaseTool):
	name = "get_runner"
	action = "get_runner"
	auto_allow = True  # read-only runner-doc lookup, like list_runners
	schema = {
		"type": "function",
		"function": {
			"name": "get_runner",
			"description": (
				"Get the LIVE status of one task / workflow / scan, running or finished: status, "
				"progress, targets, timing, child runners (workflows/scans), counts of what it found "
				"so far by type, its errors/warnings, and the `query` that scopes query_workspace to "
				"its findings. Example: get_runner(runner_id='<id>', runner_type='scan')."
			),
			"parameters": {
				"type": "object",
				"properties": {"runner_id": _RUNNER_ID_SCHEMA, "runner_type": _RUNNER_TYPE_SCHEMA},
				"required": ["runner_id"],
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Read one runner's doc from the store (every driver persists it during the run) and
		return a compact live view. Read-only, surfaced to the model only (``ai_query_result``)."""
		from secator.ai.runner_history import runner_live_view
		context = _get_result_context(action, ctx)
		runner_id = str(action.get("runner_id") or "").strip()
		if not runner_id:
			yield Error(message="get_runner needs a runner_id.", _context=context)
			return
		engine, doc, rtype, workspace_id = _runner_lookup(action, ctx)
		if doc is None:
			yield Error(message=(
				f"Runner {runner_id!r} not found in this workspace. Use a runner_id from a run result "
				f"or list_runners (`run_id`)."), _context=context)
			return
		view = runner_live_view(engine, doc, rtype, workspace_id=workspace_id)
		yield {"_type": "runner_status", **view, "_context": {**context, "ai_query_result": True}}


class StopRunner(BaseTool):
	name = "stop_runner"
	action = "stop_runner"
	# The guardrail layer allows the CALL; the ownership gate lives in the handler, which
	# needs the store: a runner this ai task (or one of its subagents) started is stopped
	# directly, any other runner only after the user approves (a permission prompt; a
	# non-interactive run denies it).
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "stop_runner",
			"description": (
				"Stop a RUNNING task / workflow / scan by id (from a run result, get_runner or "
				"list_runners). Stopping a runner you started is immediate; stopping any other runner "
				"asks the user first. What it already found stays stored. "
				"Example: stop_runner(runner_id='<id>', runner_type='task', reason='no live hosts left to probe')."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"runner_id": _RUNNER_ID_SCHEMA,
					"runner_type": _RUNNER_TYPE_SCHEMA,
					"reason": {"type": "string", "description": "Why you stop it (shown to the user)."},
				},
				"required": ["runner_id", "reason"],
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		from secator.ai.actions import _ask_and_check
		from secator.ai.interactivity import RemoteBackend
		from secator.ai.runner_history import TERMINAL_STATUSES, runner_scope, _own_ids
		context = _get_result_context(action, ctx)
		runner_id = str(action.get("runner_id") or "").strip()
		reason = str(action.get("reason") or "").strip()
		if not runner_id:
			yield Error(message="stop_runner needs a runner_id.", _context=context)
			return
		self_ids = {str(ctx.context.get(k)) for k in _SELF_ID_KEYS if ctx.context.get(k)}
		if runner_id in self_ids:
			yield Error(message="That runner is this AI run itself (or runs it): end your turn with stop instead.",
			            _context=context)
			return
		live = ctx.spawned_runners.get(runner_id)
		engine, doc, rtype, _ = _runner_lookup(action, ctx)
		if doc is None and live is None:
			yield Error(message=(
				f"Runner {runner_id!r} not found in this workspace. Use a runner_id from a run result, "
				f"get_runner or list_runners (`run_id`)."), _context=context)
			return
		rtype = rtype or getattr(getattr(live, "config", None), "type", "") or "task"
		doc_ctx = (doc or {}).get("context") or {}
		own_ai_celery = ctx.context.get("celery_id")
		runs_me = bool(own_ai_celery) and doc_ctx.get("celery_id") == own_ai_celery and not (doc or {}).get("has_parent")
		if doc is not None and (_own_ids(doc, rtype) & self_ids or runs_me):
			yield Error(message="That runner is this AI run itself (or runs it): end your turn with stop instead.",
			            _context=context)
			return
		if live is None and doc is not None:  # found by another of its ids
			live = next((ctx.spawned_runners[i] for i in _own_ids(doc, rtype) if i in ctx.spawned_runners), None)
		doc_id = runner_scope(doc, rtype)[0] if doc else runner_id
		name = (doc or {}).get("name") or getattr(getattr(live, "config", None), "name", "") or runner_id
		status = str((doc or {}).get("status") or "").upper()
		if status in TERMINAL_STATUSES or (live is not None and getattr(live, "done", False) is True):
			yield self._result(context, doc_id, rtype, name, status or "DONE", stopped=False,
			                   message=f"{rtype} {name} already finished ({status or 'done'}): nothing to stop.")
			return

		# Ownership: spawned by this ai task (recorded with its run card), or directly by a
		# subagent this ai task spawned (the runner belongs to that subagent's conversation).
		# Anything else (incl. runners of earlier ai runs or nested subagents) asks the user.
		owned = live is not None or (
			bool(doc_ctx.get("session_id")) and doc_ctx.get("session_id") in ctx.subagent_sessions)
		if not owned:
			is_remote = isinstance(ctx.backend, RemoteBackend)
			denial = yield from _ask_and_check(
				ctx, is_remote,
				question=(f"Stop {rtype} {name} ({doc_id})? It was not started by this AI run. "
				          f"Reason: {reason or 'none given'}"),
				permission_type="stop_runner",
				value=doc_id,
				deny_message=f"Not stopped: the user did not approve stopping {rtype} {name}.",
				command=f"stop_runner {rtype} {name} ({doc_id})",
				reason=reason)
			if denial:
				yield Warning(message=denial, _context=context)
				return

		# Stop through the existing paths: a runner object this process holds is stopped in
		# place (stop flag, Celery revoke of its tasks, process kill); a runner known only from
		# the store gets its Celery tasks revoked (what Runner.stop_celery_tasks revokes, plus
		# its own task id for a top-level runner; a child's celery_id may be its parent's).
		revoked, how = [], ""
		if live is not None:
			try:
				how, revoked = _stop_live_runner(live)
			except Exception as e:  # noqa: BLE001 - report the failure, never break the loop
				yield Warning(message=f"Could not stop {rtype} {name}: {e}", _context=context)
				return
		else:
			from secator.celery import revoke_task
			celery_ids = list(doc_ctx.get("celery_ids") or [])
			if not doc.get("has_parent") and doc_ctx.get("celery_id"):
				celery_ids.append(doc_ctx["celery_id"])
			celery_ids = [i for i in dict.fromkeys(celery_ids) if i and i != own_ai_celery]
			for cid in celery_ids:
				try:
					revoke_task(cid, name)
					revoked.append(cid)
				except Exception as e:  # noqa: BLE001 - report what could not be revoked
					yield Warning(message=f"Could not revoke Celery task {cid}: {e}", _context=context)
			how = "revoked its Celery tasks" if revoked else ""
		if not how:
			where = ("it runs in this process with no command or Celery task to stop right now"
			         if live is not None else "it runs inside another process and has no Celery task to revoke")
			hint = " Stop the runner it runs under instead." if (doc or {}).get("has_parent") else ""
			yield self._result(context, doc_id, rtype, name, status or "RUNNING", stopped=False, message=(
				f"Could not stop {rtype} {name}: {where}.{hint}"))
			return
		new_status = None
		if engine is not None:
			from secator.ai.runner_history import find_runner_doc
			try:
				after, _ = find_runner_doc(engine, doc_id, rtype, ctx.context.get("workspace_id") or None)
				new_status = str((after or {}).get("status") or "").upper() or None
			except Exception:  # noqa: BLE001
				new_status = None
		msg = f"Stop requested for {rtype} {name}: {how}"
		if revoked:
			msg += f" ({len(revoked)} Celery task(s) revoked)"
		msg += "."
		if new_status and new_status not in TERMINAL_STATUSES:
			msg += (f" Its stored status still reads {new_status}: it updates once the runner "
			        f"handles the stop, so check again with get_runner before relying on it.")
		yield self._result(context, doc_id, rtype, name, new_status or "STOPPING", stopped=True,
		                   message=msg, revoked=revoked, reason=reason)

	@staticmethod
	def _result(context, runner_id, rtype, name, status, stopped, message, revoked=None, reason=""):
		out = {"_type": "runner_stop", "runner_id": runner_id, "runner_type": rtype, "name": name,
		       "stopped": stopped, "status": status, "message": message}
		if revoked:
			out["revoked_celery_ids"] = revoked
		if reason:
			out["reason"] = reason
		out["_context"] = {**context, "ai_query_result": True}
		return out
