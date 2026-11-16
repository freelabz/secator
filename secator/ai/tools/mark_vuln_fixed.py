"""AI tool: `mark_vuln_fixed`."""
from secator.ai.tools.base import BaseTool, _SCAN_EXPLOIT_MONITOR


class MarkVulnFixed(BaseTool):
	name = "mark_vuln_fixed"
	action = "mark_vuln_fixed"
	modes = _SCAN_EXPLOIT_MONITOR
	auto_allow = True
	handler = "_handle_mark_vuln_fixed"
	schema = {
		"type": "function",
		"function": {
			"name": "mark_vuln_fixed",
			"description": (
				"Mark an EXISTING vulnerability as FIXED — a REAL vulnerability (typically one previously "
				"confirmed EXPLOITED) that no longer reproduces because it has been remediated/patched. "
				"Identify it by the `_uuid` from query_workspace results. Sets status='FIXED' but keeps the vuln "
				"VISIBLE (does NOT hide it) — it is a resolved part of the history, not a false positive. Use this "
				"(NOT mark_vuln_false_positive) when the vuln WAS genuine but is now gone/closed. Give a short "
				"`reason` (what changed). Prefer pairing it with an `add_note` recording the evidence that it is gone."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark fixed (from query_workspace results)."
					},
					"reason": {
						"type": "string",
						"description": "Short reason it's now fixed (e.g. 'patched to 1.2.4', 'endpoint removed'). Recorded on the vuln."  # noqa: E501
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
