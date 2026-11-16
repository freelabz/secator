"""AI tool: `run_workflow`."""
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA


class RunWorkflow(BaseTool):
	name = "run_workflow"
	action = "workflow"
	handler = "_handle_workflow"
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
