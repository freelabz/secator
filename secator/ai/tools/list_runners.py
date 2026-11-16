"""AI tool: `list_runners`."""
from secator.ai.tools.base import BaseTool, _READONLY_HELPER


class ListRunners(BaseTool):
	name = "list_runners"
	action = "list_runners"
	modes = _READONLY_HELPER
	auto_allow = True  # read-only run-history lookup; no mutation, no target/path egress
	handler = "_handle_list_runners"
	schema = {
		"type": "function",
		"function": {
			"name": "list_runners",
			"description": (
				"List the run history of this workspace — the scans / workflows / tasks that have run, "
				"newest first, with their status, targets and timing. Use it to answer questions like "
				"'which scans ran in the last 24h?' or 'what failed recently?'. This lists RUN activity; "
				"use query_workspace for the findings those runs produced."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"runner_type": {
						"type": "string",
						"enum": ["scan", "workflow", "task"],
						"description": "Filter to one runner type (e.g. 'scan'). Omit to list all types."
					},
					"since": {
						"type": "string",
						"description": "Only runners started within this window: a relative age like '24h', '7d', '30m', '2w', or an ISO-8601 date/datetime. Omit for no time filter."  # noqa: E501
					},
					"status": {
						"type": "string",
						"description": "Filter by run status (e.g. 'SUCCESS', 'FAILURE', 'RUNNING'). Omit for any."
					},
					"include_children": {
						"type": "boolean",
						"description": "Include nested child runners (a scan's sub-workflows/tasks). Default false = top-level runs only."  # noqa: E501
					},
					"limit": {
						"type": "integer",
						"description": "Maximum runners to return (default 50).",
						"default": 50
					}
				},
				"required": []
			}
		}
	}
