"""AI tool: `add_note`."""
from secator.ai.tools.base import BaseTool, _SCAN_EXPLOIT_MONITOR


class AddNote(BaseTool):
	name = "add_note"
	action = "add_note"
	modes = _SCAN_EXPLOIT_MONITOR
	auto_allow = True
	handler = "_handle_add_note"
	schema = {
		"type": "function",
		"function": {
			"name": "add_note",
			"description": (
				"Attach a NOTE (an append-only annotation) to an EXISTING finding, identified by the `_uuid` "
				"from query_workspace results. Use it to record WHY you reached a conclusion, what you observed, "
				"or what changed on a finding between runs — without modifying the finding itself. The note is "
				"stored separately and keyed to the finding's stable identity, so it stays attached even after a "
				"re-scan. Give a clear `body`; when you are recording that specific fields CHANGED, also pass "
				"`changes` so the delta is structured. For a false-positive / exploited verdict use the dedicated "
				"mark_vuln_* tools instead — a note does not change status."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the finding to annotate (from query_workspace results)."
					},
					"body": {
						"type": "string",
						"description": "The note text (plain English / markdown). Required."
					},
					"changes": {
						"type": "array",
						"description": (
							"Optional structured list of field changes to record alongside the note, one entry per "
							"changed field: {\"field\": \"<name>\", \"old\": <before>, \"new\": <after>}."
						),
						"items": {
							"type": "object",
							"properties": {
								"field": {"type": "string", "description": "The finding field that changed."},
								"old": {"description": "The previous value."},
								"new": {"description": "The new value."}
							},
							"required": ["field"]
						}
					}
				},
				"required": ["_uuid", "body"]
			}
		}
	}
