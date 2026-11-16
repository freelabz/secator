"""AI tool: `run_subagent`."""
from typing import Dict, Generator
from secator.output_types import Error
from secator.ai.prompts import normalize_mode
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._runner import _run_runner
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA, _SUBAGENT_BACKGROUND_SCHEMA


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
				"non-interactively and hands back a summary — the ONLY way to spawn a subagent (do NOT "
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
					"background": _SUBAGENT_BACKGROUND_SCHEMA,
					"mode": {
						"type": "string",
						"enum": ["chat", "scan", "exploit"],
						"description": "Optional mode for the subagent (chat/scan/exploit). Honored only in an "
						               "auto or scan session; ignored/forced to chat in a pinned chat session. "
						               "Omit to inherit the current mode."
					},
					"model": {
						"type": "string",
						"description": "Optional LLM model id for the subagent. Omit to inherit the current model."
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
		opts = {"prompt": objective, "mode": child_mode}
		model = (action.get("model") or "").strip()
		if model:
			opts["model"] = model
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
