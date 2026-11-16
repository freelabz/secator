"""AI tool: `change_mode`."""
from secator.ai.tools.base import BaseTool, _CAN_CHANGE_MODE


class ChangeMode(BaseTool):
	name = "change_mode"
	action = "change_mode"
	modes = _CAN_CHANGE_MODE  # NOT contribute / research / monitor (terminal or bounded, directly-selected)
	auto_allow = True
	handler = "_handle_change_mode"
	schema = {
		"type": "function",
		"function": {
			"name": "change_mode",
			"description": (  # noqa: E501
				"Switch your OWN operating mode when the task needs capabilities your current mode lacks. "
				"If you are in read-only chat and the user asks you to scan, do recon, attack, or exploit, "
				"call change_mode(mode='scan') and then carry out the request — do NOT ask the user to "
				"switch modes, change it yourself. 'scan' unlocks tasks/workflows/shell + finding writes; "
				"'exploit' is for focused exploitation of a known vulnerability. "
				"Example (good): change_mode(mode='scan', reason='user asked to run reconnaissance')."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"mode": {
						"type": "string",
						"enum": ["scan", "exploit"],
						"description": "The mode to switch to: 'scan' (recon/scanning/active testing) or 'exploit'."
					},
					"reason": {
						"type": "string",
						"description": "Short reason for the switch (optional)."
					}
				},
				"required": ["mode"]
			}
		}
	}
