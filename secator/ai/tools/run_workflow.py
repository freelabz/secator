"""AI tool: `run_workflow`."""
from typing import Dict, Generator
from secator.ai.actions import ActionContext
from secator.ai.tools._runner import _run_runner
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA


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
