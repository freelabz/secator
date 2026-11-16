"""AI tool: `add_finding`."""
from secator.ai.tools.base import BaseTool, _ACTIVE_MODES


class AddFinding(BaseTool):
	name = "add_finding"
	action = "add_finding"
	modes = _ACTIVE_MODES
	auto_allow = True
	handler = "_handle_add_finding"
	schema = {
		"type": "function",
		"function": {
			"name": "add_finding",
			"description": "Add a security finding to the workspace (e.g. vulnerability, exploit, url). "
			               "Put the finding's data inside `fields` (NOT as top-level args). "
			               "Example (good): add_finding(_type='vulnerability', fields={'name': 'SQLi in login', 'matched_at': 'http://x/login', 'severity': 'high'}). "  # noqa: E501
			               "Bad: add_finding(_type='vulnerability', name='x') — name/matched_at/... must go inside `fields`.",  # noqa: E501
			"parameters": {
				"type": "object",
				"properties": {
					"_type": {
						"type": "string",
						"description": "The finding type (e.g. vulnerability, exploit, url, port)."
					},
					"fields": {
						"type": "object",
						"description": (
							"The finding's fields for this `_type` (fields vary by type, so put ALL of them "
							"here, e.g. {\"name\": \"SQLi in login\", \"matched_at\": \"http://x/login\", "
							"\"severity\": \"high\"}). MUST be a nested object — passing these as top-level args "
							"makes strict function-calling providers drop them. List fields must be JSON arrays; "
							"`extra_data` must be an object."
						),
						"additionalProperties": True
					}
				},
				"required": ["_type", "fields"],
				"additionalProperties": True
			}
		}
	}
