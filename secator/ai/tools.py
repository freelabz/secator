"""Tool schema definitions for native LLM tool calling."""

from secator.ai.prompts import get_mode_config

# Map tool names to action types used by existing action handlers
TOOL_ACTION_MAP = {
	"run_task": "task",
	"run_workflow": "workflow",
	"run_shell": "shell",
	"query_workspace": "query",
	"follow_up": "follow_up",
	"add_finding": "add_finding",
}

# Reverse mapping: action type -> tool name
ACTION_TOOL_MAP = {v: k for k, v in TOOL_ACTION_MAP.items()}

# OpenAI-format tool schemas keyed by tool name
TOOL_SCHEMAS = {
	"run_task": {
		"type": "function",
		"function": {
			"name": "run_task",
			"description": "Run a secator security task (e.g. nmap, httpx, nuclei) against one or more targets.",
			"parameters": {
				"type": "object",
				"properties": {
					"name": {
						"type": "string",
						"description": "The task name (e.g. nmap, httpx, nuclei, ffuf)."
					},
					"targets": {
						"type": "array",
						"items": {"type": "string"},
						"description": "List of targets (hosts, URLs, IPs)."
					},
					"opts": {
						"type": "object",
						"description": "Optional task-specific options (e.g. ports, rate_limit, timeout)."
					}
				},
				"required": ["name", "targets"]
			}
		}
	},
	"run_workflow": {
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
					"targets": {
						"type": "array",
						"items": {"type": "string"},
						"description": "List of targets (hosts, URLs, IPs)."
					},
					"opts": {
						"type": "object",
						"description": "Optional workflow options (e.g. profiles)."
					}
				},
				"required": ["name", "targets"]
			}
		}
	},
	"run_shell": {
		"type": "function",
		"function": {
			"name": "run_shell",
			"description": "Run an arbitrary shell command for exploration, exploitation, or data analysis.",
			"parameters": {
				"type": "object",
				"properties": {
					"command": {
						"type": "string",
						"description": "The shell command to execute."
					}
				},
				"required": ["command"]
			}
		}
	},
	"query_workspace": {
		"type": "function",
		"function": {
			"name": "query_workspace",
			"description": "Query the workspace database for stored security findings using MongoDB-style queries.",
			"parameters": {
				"type": "object",
				"properties": {
					"query": {
						"type": "object",
						"description": "MongoDB-style query object (e.g. {\"_type\": \"vulnerability\", \"severity\": {\"$in\": [\"critical\", \"high\"]}})."  # noqa: E501
					},
					"limit": {
						"type": "integer",
						"description": "Maximum number of results to return.",
						"default": 100
					}
				},
				"required": ["query"]
			}
		}
	},
	"follow_up": {
		"type": "function",
		"function": {
			"name": "follow_up",
			"description": "Ask the user a follow-up question to clarify next steps or present options.",
			"parameters": {
				"type": "object",
				"properties": {
					"reason": {
						"type": "string",
						"description": "Why follow-up is needed."
					},
					"choices": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Optional list of concrete action choices for the user."
					}
				},
				"required": ["reason"]
			}
		}
	},
	"add_finding": {
		"type": "function",
		"function": {
			"name": "add_finding",
			"description": "Add a security finding to the workspace (e.g. vulnerability, exploit, url).",
			"parameters": {
				"type": "object",
				"properties": {
					"_type": {
						"type": "string",
						"description": "The finding type (e.g. vulnerability, exploit, url, port)."
					}
				},
				"required": ["_type"],
				"additionalProperties": True
			}
		}
	},
}


def build_tool_schemas(mode: str) -> list:
	"""Return list of tool schemas filtered by mode's allowed_actions.

	Args:
		mode: The AI mode (attack, chat, exploiter). Unknown modes fall back to chat.

	Returns:
		List of OpenAI-format tool schema dicts.
	"""
	config = get_mode_config(mode)
	allowed_actions = config["allowed_actions"]
	return [
		schema for tool_name, schema in TOOL_SCHEMAS.items()
		if TOOL_ACTION_MAP.get(tool_name) in allowed_actions
	]


def tool_call_to_action(tool_name: str, arguments: dict) -> dict | None:
	"""Convert a tool call to an action dict compatible with existing action handlers.

	Args:
		tool_name: The tool function name from the LLM response.
		arguments: The parsed arguments dict from the LLM response.

	Returns:
		Action dict with "action" key added, or None for unknown tools.
	"""
	action_type = TOOL_ACTION_MAP.get(tool_name)
	if action_type is None:
		return None
	return {"action": action_type, **arguments}
