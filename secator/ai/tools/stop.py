"""AI tool: `stop`."""
from secator.ai.tools.base import BaseTool


class Stop(BaseTool):
	name = "stop"
	action = "stop"
	auto_allow = True
	# NOT emitted by build_tool_schemas / not in TOOL_SCHEMAS — injected per-backend
	# via get_extra_tools (interactive backends a `stop` with `choices`, AutoBackend a
	# choiceless one). The registry carries the INTERACTIVE schema so coerce_stringified_args
	# can coerce a stringified `choices` array; the choiceless variant is STOP_TOOL_SCHEMA_SIMPLE.
	injected = True
	handler = "_handle_stop"
	schema = {
		"type": "function",
		"function": {
			"name": "stop",
			"description": "End your turn. Call when the user's request has been fulfilled, or when you hit a blocker "  # noqa: E501
			               "you cannot resolve without user input. Offer concrete next steps via `choices` (renders as "  # noqa: E501
			               "clickable buttons) only when each is executable as-is; omit `choices` when the task is "  # noqa: E501
			               "simply complete or when asking an open question (e.g. which target) — ask it in `reason`.",
			"parameters": {
				"type": "object",
				"properties": {
					"reason": {
						"type": "string",
						"description": "Why you are stopping (summary of accomplishments or description of blocker)."
					},
					"choices": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Optional list of concrete actions you can execute as-is, or known options to pick from. "  # noqa: E501
						               "Never a choice that asks the user to provide input (e.g. 'Provide a target')."
					},
					"multiple": {
						"type": "boolean",
						"description": "Set true when the choices are NOT mutually exclusive and the user could pick SEVERAL "  # noqa: E501
						               "(multi-select) — common for independent next actions, e.g. ['Port scan', 'Directory "  # noqa: E501
						               "brute-force', 'Vulnerability scan'] the user may want to run together. Omit or false "  # noqa: E501
						               "only for a genuine pick-exactly-one question (e.g. 'Which target?')."
					}
				},
				"required": ["reason"]
			}
		}
	}


# The registry: order mirrors the historical TOOL_SCHEMAS order so build_tool_schemas
# emits tools in the same order as before (parity).
