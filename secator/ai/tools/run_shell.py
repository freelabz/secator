"""AI tool: `run_shell`."""
from secator.ai.tools.base import BaseTool, _DESCRIPTION_SCHEMA, _SHELL_MODES


class RunShell(BaseTool):
	name = "run_shell"
	action = "shell"
	modes = _SHELL_MODES
	handler = "_handle_shell"
	schema = {
		"type": "function",
		"function": {
			"name": "run_shell",
			"description": "Run an arbitrary shell command for exploration, exploitation, or data analysis. "
			               "Commands default to a 30s timeout; if one times out and just needs longer (a slow "
			               "install, a long scan), re-run it with a higher `timeout`. "
			               "Example (good): run_shell(command='curl -sk https://10.0.0.1/ | head -50', description='Grab the HTTP banner'). "  # noqa: E501
			               "Bad: run_shell() — no command.",
			"parameters": {
				"type": "object",
				"properties": {
					"command": {
						"type": "string",
						"description": "The shell command to execute."
					},
					"timeout": {
						"type": "integer",
						"description": "Optional max run time in seconds for THIS command (default 30). Raise it for a "
						               "slow command (install, long scan) and re-run after a timeout. Capped at the "
						               "server's configured maximum task timeout; values below the default are floored."  # noqa: E501
					},
					"description": _DESCRIPTION_SCHEMA
				},
				"required": ["command", "description"]
			}
		}
	}
