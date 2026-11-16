"""AI tool: `change_mode`."""
from typing import Dict, Generator
from secator.output_types import Ai, Error, Info
from secator.ai.prompts import normalize_mode
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool


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
