"""AI tool: `web_search`."""
from secator.ai.tools.base import BaseTool


class WebSearch(BaseTool):
	name = "web_search"
	action = "web_search"
	auto_allow = True  # read-only external lookup; no workspace mutation, no target scope
	handler = "_handle_web_search"
	schema = {
		"type": "function",
		"function": {
			"name": "web_search",
			"description": (
				"Search the public web for live external context — CVE write-ups, PoC/exploit repos, "
				"tool docs, hardening notes. Use this for information NOT in the workspace; use "
				"query_workspace for stored findings. Targets/scope are NOT checked (this reads public "
				"sources, it does not touch the engagement targets)."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"query": {
						"type": "string",
						"description": "The search query. Keep it short and keyword-focused; write it in English (engines index English best)."  # noqa: E501
					},
					"mode": {
						"type": "string",
						"enum": ["answer", "links", "exploit"],
						"description": (
							"What you need back (default 'answer'). 'answer' — a synthesized answer over live "
							"sources when configured, else result links. 'links' — a list of source links with "
							"snippets. 'exploit' — exploit code, PoCs and offensive tools (searches Sploitus)."
						)
					},
					"max_results": {
						"type": "integer",
						"description": "Maximum number of results (1-25; default 5).",
						"default": 5
					},
					"exploit_type": {
						"type": "string",
						"enum": ["exploits", "tools"],
						"description": "exploit mode only: 'exploits' (default) for exploit code/PoCs, 'tools' for offensive-security tools."  # noqa: E501
					},
					"sort": {
						"type": "string",
						"enum": ["default", "date", "score"],
						"description": "exploit mode only: order by relevance (default), date (newest), or score (highest CVSS)."  # noqa: E501
					}
				},
				"required": ["query"]
			}
		}
	}
