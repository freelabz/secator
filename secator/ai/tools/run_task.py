"""AI tool: `run_task`."""
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA


class RunTask(BaseTool):
	name = "run_task"
	action = "task"
	handler = "_handle_task"
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
