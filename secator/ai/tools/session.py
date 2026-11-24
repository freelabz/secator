"""AI tools that steer the agent session itself: ``update_plan`` (the working plan),
``change_mode`` (switch mode) and ``stop`` (end the turn).
"""
import json
from typing import Dict, Generator
from secator.output_types import Ai, Error, Info
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool
from secator.ai.prompts import normalize_mode


# ---------- update_plan ----------

_PLAN_STATUSES = ("pending", "in_progress", "done", "skipped")


_MAX_PLAN_ITEMS = 30


_MAX_PLAN_TEXT = 300


class UpdatePlan(BaseTool):
	name = "update_plan"
	action = "update_plan"
	auto_allow = True  # a user-visible to-do list; no workspace mutation, no target/path egress
	schema = {
		"type": "function",
		"function": {
			"name": "update_plan",
			"description": (
				"Maintain a short, user-visible to-do list for a multi-step task. Call it to lay out your "
				"plan, and AGAIN each time a step's state changes (mark one in_progress, then done). Pass the "
				"WHOLE list every time — it replaces the current plan. Keep exactly one step in_progress. Use "
				"it for genuinely multi-step work (recon -> enumerate -> exploit), not for a single action."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"items": {
						"type": "array",
						"description": "The full ordered to-do list (replaces the previous one).",
						"items": {
							"type": "object",
							"properties": {
								"text": {"type": "string", "description": "Short description of the step."},
								"status": {"type": "string", "enum": ["pending", "in_progress", "done", "skipped"], "description": "Step state (default pending)."}  # noqa: E501
							},
							"required": ["text"]
						}
					}
				},
				"required": ["items"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Maintain a user-visible to-do list for a multi-step task.

		Each call REPLACES the whole plan (the model sends the full ordered list); the latest
		Ai(ai_type="plan") doc is the current plan. Read-only wrt the workspace
		(no findings, no targets) — auto-allowed. Normalizes/validates items so a malformed status
		or a giant list can't break the renderer.
		"""
		context = _get_result_context(action, ctx)
		items = action.get("items", [])
		if isinstance(items, str):
			try:
				items = json.loads(items)
			except (json.JSONDecodeError, TypeError):
				items = None
		if not isinstance(items, list) or not items:
			yield Error(message="update_plan requires a non-empty `items` list of {text, status}.", _context=context)
			return

		norm = []
		for raw in items[:_MAX_PLAN_ITEMS]:
			if isinstance(raw, str):
				raw = {"text": raw}
			if not isinstance(raw, dict):
				continue
			text = str(raw.get("text") or "").strip()
			if not text:
				continue
			if ctx.encryptor:
				text = _decrypt_dict({"text": text}, ctx.encryptor).get("text", text)
			status = str(raw.get("status") or "pending").strip().lower()
			if status not in _PLAN_STATUSES:
				status = "pending"
			norm.append({"text": text[:_MAX_PLAN_TEXT], "status": status})
		if not norm:
			yield Error(message="update_plan: no valid items (each needs a non-empty `text`).", _context=context)
			return

		done = sum(1 for i in norm if i["status"] in ("done", "skipped"))
		total = len(norm)
		current = next((i["text"] for i in norm if i["status"] == "in_progress"), "")
		yield Ai(
			content=current or f"{done}/{total} steps done",
			ai_type="plan",
			extra_data={"items": norm, "done": done, "total": total},
			_context=context,
		)


# ---------- change_mode ----------

class ChangeMode(BaseTool):
	name = "change_mode"
	action = "change_mode"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "change_mode",
			"description": (  # noqa: E501
				"Switch your OWN operating mode when the task needs capabilities your current mode lacks. "
				"If you are in read-only chat and the user asks you to scan, do recon, attack, or exploit, "
				"call change_mode(mode='scan') and then carry out the request — do NOT ask the user to "
				"switch modes, change it yourself. 'scan' unlocks tasks/workflows/shell + finding writes; "
				"'exploit' is for focused exploitation of a known vulnerability. "
				"Example (good): change_mode(mode='scan', reason='user asked to run reconnaissance')."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"mode": {
						"type": "string",
						"enum": ["scan", "exploit"],
						"description": "The mode to switch to: 'scan' (recon/scanning/active testing) or 'exploit'."
					},
					"reason": {
						"type": "string",
						"description": "Short reason for the switch (optional)."
					}
				},
				"required": ["mode"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Handle a model-driven mode change.

		Signals the requested mode back to the loop via ``Ai(ai_type="mode_changed")``;
		the runner applies it (rebuilds the tool surface + persona and continues the turn).
		The loop treats this as a normal tool result (the call still gets a response, since
		the turn continues).

		Gating: a user-PINNED read-only ``chat`` session can never self-escape — the tool
		is not even built for it (see ``build_tool_schemas``); this rejects it as defense in
		depth. Self-de-escalation is not allowed (no capability benefit), so the only valid
		targets are ``scan``/``exploit`` (legacy ``attack`` is accepted as ``scan``).
		"""
		context = _get_result_context(action, ctx)
		requested = normalize_mode(action.get("mode") or "")
		if (not getattr(ctx, "mode_is_auto", True)) and ctx.mode == "chat":
			yield Error(
				message="Cannot change mode: this session is pinned to read-only chat. "
				"Ask the user to switch the mode to 'auto' or an action mode.",
				_context=context)
			return
		if requested not in ("scan", "exploit"):
			yield Error(
				message=f"Invalid change_mode target '{requested}'. Choose 'scan' or 'exploit'.",
				_context=context)
			return
		# change_mode only escalates — it can't de-escalate (e.g. exploit -> scan), which
		# would silently drop capability. Rank chat < scan < exploit; reject anything that
		# isn't a strict escalation from the current mode. (`auto` ranks below all, so an auto
		# session can still escalate to either.)
		_rank = {"chat": 0, "scan": 1, "exploit": 2}
		current = normalize_mode(getattr(ctx, "mode", "") or "")
		# Already in the requested mode -> benign no-op, NOT a de-escalation. The model
		# sometimes re-requests its current mode (e.g. unsure which mode it is in); surface a
		# calm Info ("already there, proceed"), never a scary error.
		if _rank[requested] == _rank.get(current, -1):
			yield Info(
				message=f"Already in '{current}' mode — no change needed; continue with the task.",
				_context=context)
			return
		if _rank[requested] < _rank.get(current, -1):
			yield Error(
				message=f"Cannot change mode from '{current}' to '{requested}': change_mode "
				"only escalates (e.g. scan -> exploit), it cannot de-escalate.",
				_context=context)
			return
		yield Ai(content=requested, ai_type="mode_changed", _context=context)


# ---------- stop ----------

class Stop(BaseTool):
	name = "stop"
	action = "stop"
	auto_allow = True
	# NOT emitted by build_tool_schemas / not in TOOL_SCHEMAS — injected per-backend
	# via get_extra_tools (interactive backends a `stop` with `choices`, AutoBackend a
	# choiceless one). The registry carries the INTERACTIVE schema so coerce_stringified_args
	# can coerce a stringified `choices` array; the choiceless variant is STOP_TOOL_SCHEMA_SIMPLE.
	injected = True
	schema = {
		"type": "function",
		"function": {
			"name": "stop",
			"description": "End your turn. Call when the user's request has been fulfilled, or when you hit a blocker "  # noqa: E501
			               "you cannot resolve without user input. Offer concrete next steps via `choices` (renders as "  # noqa: E501
			               "clickable buttons) only when each is executable as-is; omit `choices` when the task is "  # noqa: E501
			               "simply complete or when asking an open question (e.g. which target) — ask it in `reason`.",
			"parameters": {
				"type": "object",
				"properties": {
					"reason": {
						"type": "string",
						"description": "Why you are stopping (summary of accomplishments or description of blocker)."
					},
					"choices": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Optional list of concrete actions you can execute as-is, or known options to pick from. "  # noqa: E501
						               "Never a choice that asks the user to provide input (e.g. 'Provide a target')."
					},
					"multiple": {
						"type": "boolean",
						"description": "Set true when the choices are NOT mutually exclusive and the user could pick SEVERAL "  # noqa: E501
						               "(multi-select) — common for independent next actions, e.g. ['Port scan', 'Directory "  # noqa: E501
						               "brute-force', 'Vulnerability scan'] the user may want to run together. Omit or false "  # noqa: E501
						               "only for a genuine pick-exactly-one question (e.g. 'Which target?')."
					}
				},
				"required": ["reason"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Handle the stop action — the SINGLE end-of-turn signal in every mode.

		Always yields an ``Ai(ai_type="stopped")`` carrying the model's ``reason`` and any
		``choices``/``multiple`` it offered. The loop decides what happens next from the
		backend's ask_user: an interactive backend turns this into an end-of-turn pause
		(the user can pick a choice / type a reply), a non-interactive backend ends.

		``choices`` is stored on the top-level ``choices`` field (what clients read) AND in
		``extra_data`` (back-compat). Without the top-level field, the persisted doc has
		``choices: []`` and clients render no choice buttons. ``multiple`` tells clients to
		render multi-select (checkboxes) vs single-pick.
		"""
		context = _get_result_context(action, ctx)
		reason = action.get("reason", "completed")
		choices = action.get("choices", []) or []
		multiple = bool(action.get("multiple", False))
		yield Ai(
			content=reason, ai_type="stopped", choices=choices, multiple=multiple,
			extra_data={"choices": choices, "multiple": multiple}, _context=context)
