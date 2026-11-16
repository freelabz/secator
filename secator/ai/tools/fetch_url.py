"""AI tool: `fetch_url`."""
from secator.ai.tools.base import BaseTool, _READONLY_HELPER


class FetchUrl(BaseTool):
	name = "fetch_url"
	action = "fetch_url"
	modes = _READONLY_HELPER
	auto_allow = True  # read-only external lookup; SSRF-guarded in the handler, no target scope
	handler = "_handle_fetch_url"
	schema = {
		"type": "function",
		"function": {
			"name": "fetch_url",
			"description": (
				"Fetch a single PUBLIC web page and return its readable text — use it to READ a page you "
				"already know (a HackTricks technique, a vendor advisory, a Debian security-tracker page, a "
				"blog post on a fresh CVE). Only public "
				"http(s) pages are allowed; internal/private hosts are refused."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "The http(s) URL to fetch."},
					"max_chars": {"type": "integer", "description": "Max characters of extracted text to return (default 20000)."}
				},
				"required": ["url"]
			}
		}
	}
