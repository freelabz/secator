"""Tool schema definitions for native LLM tool calling."""

import json

from secator.ai.prompts import get_mode_config

# Map tool names to action types used by existing action handlers
TOOL_ACTION_MAP = {
	"run_task": "task",
	"run_workflow": "workflow",
	"run_shell": "shell",
	"query_workspace": "query",
	"follow_up": "follow_up",
	"add_finding": "add_finding",
	"stop": "stop",
}

# OpenAI-format tool schemas keyed by tool name
TOOL_SCHEMAS = {
	"run_task": {
		"type": "function",
		"function": {
			"name": "run_task",
			"description": "Run a secator security task (e.g. nmap, httpx, nuclei, ai) against targets. Use name 'ai' to spawn an AI subagent.",  # noqa: E501
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
						"description": "Optional task-specific options (e.g. ports, rate_limit). Control/security flags are ignored."
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
						"description": "Optional workflow options (e.g. profiles). Control/security flags are ignored."
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


# Stop tool schema — NOT in TOOL_SCHEMAS (injected by AutoBackend via get_extra_tools)
STOP_TOOL_SCHEMA = {
	"type": "function",
	"function": {
		"name": "stop",
		"description": "Stop the current session. Call when the user request has been fulfilled or when you encounter a blocker that cannot be resolved without user input.",  # noqa: E501
		"parameters": {
			"type": "object",
			"properties": {
				"reason": {
					"type": "string",
					"description": "Why you are stopping (summary of accomplishments or description of blocker)."
				}
			},
			"required": ["reason"]
		}
	}
}


def build_tool_schemas(mode: str, is_subagent: bool = False, backend=None) -> list:
	"""Return list of tool schemas filtered by mode's allowed_actions.

	Args:
		mode: The AI mode (attack, chat, exploit). Unknown modes fall back to chat.
		is_subagent: If True, exclude follow_up tool (legacy compat).
		backend: Optional interactivity backend for exclusion/extra tools.

	Returns:
		List of OpenAI-format tool schema dicts.
	"""
	config = get_mode_config(mode)
	allowed_actions = config["allowed_actions"]
	excluded = set()
	if is_subagent:
		excluded.add("follow_up")
	if backend is not None:
		excluded.update(backend.get_excluded_tools())
	schemas = [
		schema for tool_name, schema in TOOL_SCHEMAS.items()
		if TOOL_ACTION_MAP.get(tool_name) in allowed_actions
		and tool_name not in excluded
	]
	if backend is not None:
		schemas.extend(backend.get_extra_tools())
	return schemas


def coerce_stringified_args(tool_name: str, arguments: dict) -> dict:
	"""Coerce args the model serialized as JSON strings back to their declared type.

	Some providers stringify nested object/array parameters even when the tool
	schema says ``type: object`` / ``array`` (e.g. ``opts`` or ``query`` arriving
	as a JSON string). Downstream handlers then call ``.get()`` / ``**opts`` /
	``.items()`` on a ``str`` and raise ``AttributeError`` — or silently drop the
	value (``_sanitize_child_opts`` returns ``{}`` for a non-dict). Parse any such
	arg once, here at the tool-call boundary, so every consumer gets the declared
	type. Best-effort: an unparseable value is left as-is so the handler can return
	a clean error rather than crash.

	Must run BEFORE arg decryption — ``_decrypt_dict`` would otherwise treat a
	stringified object as a single encrypted value.
	"""
	if not isinstance(arguments, dict):
		return arguments
	props = TOOL_SCHEMAS.get(tool_name, {}).get("function", {}).get("parameters", {}).get("properties", {})
	for key, spec in props.items():
		if spec.get("type") in ("object", "array") and isinstance(arguments.get(key), str):
			try:
				arguments[key] = json.loads(arguments[key])
			except (json.JSONDecodeError, TypeError, ValueError):
				pass
	return arguments


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
	if not arguments:
		return None
	# A model may emit non-object arguments (a bare JSON int/array/string, e.g.
	# `12345` or `["nmap"]`). `.items()` below would raise AttributeError and abort
	# the whole loop — reject cleanly instead so the caller feeds an error back and
	# the conversation continues.
	if not isinstance(arguments, dict):
		return None
	safe_arguments = {k: v for k, v in arguments.items() if k not in {"action", "description"}}
	descr = safe_arguments.get("name", "") or safe_arguments.get("query") or safe_arguments.get("command", "unknown")
	return {"action": action_type, "description": descr, **safe_arguments}
