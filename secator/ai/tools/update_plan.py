"""AI tool: `update_plan`."""
from secator.ai.tools.base import BaseTool, _READONLY_HELPER


class UpdatePlan(BaseTool):
	name = "update_plan"
	action = "update_plan"
	modes = _READONLY_HELPER
	auto_allow = True  # a user-visible to-do list; no workspace mutation, no target/path egress
	handler = "_handle_update_plan"
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
