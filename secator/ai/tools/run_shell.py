"""AI tool: `run_shell`."""
from typing import Dict, Generator
from secator.runners import Task
from secator.output_types import Ai, Error, Info
from secator.ai.utils import _denied_secret_read, _sanitized_env, _scrub_secrets, _truncate
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._runner import _child_preamble, _child_run_opts
from secator.ai.tools._sandbox import _ensure_sandbox_container, _sandbox_container_name, _wrap_docker_exec
from secator.ai.tools.base import BaseTool, _DESCRIPTION_SCHEMA


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
