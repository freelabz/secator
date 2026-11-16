"""AI tool: `run_subagent`."""
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA, _DESCRIPTION_SCHEMA


class RunSubagent(BaseTool):
	name = "run_subagent"
	action = "subagent"
	auto_allow = True
	handler = "_handle_subagent"
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
