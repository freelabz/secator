"""AI tool: `run_task`."""
from typing import Dict, Generator
from secator.output_types import Error
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._runner import _run_runner
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA


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
		if (action.get("name") or "").strip().lower() == "ai":
			yield Error(
				message="To spawn an AI subagent, use the run_subagent tool, not run_task(name=\"ai\").",
				_context=_get_result_context(action, ctx),
			)
			return
		yield from _run_runner(action, ctx, "task")
