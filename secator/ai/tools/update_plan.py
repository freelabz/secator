"""AI tool: `update_plan`."""
import json
from typing import Dict, Generator
from secator.output_types import Ai, Error
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool


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
