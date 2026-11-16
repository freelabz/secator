"""AI tool: `mark_vuln_false_positive`."""
from secator.ai.tools.base import BaseTool, _SCAN_EXPLOIT_MONITOR


class MarkVulnFalsePositive(BaseTool):
	name = "mark_vuln_false_positive"
	action = "mark_vuln_false_positive"
	modes = _SCAN_EXPLOIT_MONITOR
	auto_allow = True
	handler = "_handle_mark_vuln_false_positive"
	schema = {
		"type": "function",
		"function": {
			"name": "mark_vuln_false_positive",
			"description": (
				"Mark an EXISTING vulnerability as a false positive when you determined it could NOT be "
				"exploited (scanner false positive, not reachable, already patched). Identify it by the `_uuid` "
				"from query_workspace results. The vuln is hidden from reports (is_false_positive=true, "
				"status='FALSE_POSITIVE') but KEPT and recoverable — never deleted. Give a short `reason`."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark false positive (from query_workspace results)."
					},
					"reason": {
						"type": "string",
						"description": "Short reason why it's a false positive (e.g. 'not reachable', 'patched'). Recorded on the vuln."  # noqa: E501
					},
					"extra_data": {
						"type": "object",
						"description": "Extra structured context merged into the vuln (existing keys preserved). Optional.",
						"additionalProperties": True
					}
				},
				"required": ["_uuid"]
			}
		}
	}
