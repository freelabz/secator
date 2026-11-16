"""AI tool: `fetch_url`."""
from typing import Dict, Generator
from secator.output_types import Ai, Error
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool


class FetchUrl(BaseTool):
	name = "fetch_url"
	action = "fetch_url"
	auto_allow = True  # read-only external lookup; SSRF-guarded in the handler, no target scope
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

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Fetch one public page and surface its readable text to the model.

		Target-agnostic (reads public sources, not the engagement targets) so it is not
		scope-gated — but the fetch is SSRF-guarded (public http(s) hosts only; internal /
		metadata / private hosts and non-http schemes are refused) so it can't be used to reach
		our own internal surface. Read-only: the page text is observation-only (marked
		ai_query_result), never persisted as a finding. Fails soft.
		"""
		from secator.ai.fetch_url import fetch_url
		context = _get_result_context(action, ctx)
		url = action.get("url", "")
		if ctx.encryptor and isinstance(url, str):
			url = _decrypt_dict({"url": url}, ctx.encryptor).get("url", url)
		url = str(url or "").strip()
		if not url:
			yield Error(message="fetch_url requires a `url`.", _context=context)
			return
		max_chars = action.get("max_chars", 20000)

		result, error = fetch_url(url, max_chars=max_chars)
		if error:
			yield Error(message=f"fetch_url: {error}", _context=context)
			return

		yield Ai(
			content=result.get("text", ""),
			ai_type="fetch_url",
			extra_data={
				"url": result.get("url"),
				"status": result.get("status"),
				"title": result.get("title"),
				"content_type": result.get("content_type"),
				"truncated": result.get("truncated"),
				"ai_query_result": True,
			},
			_context=context,
		)
		# Surface the extracted text to the model as an observation-only result.
		yield {
			"_type": "web_page",
			"url": result.get("url"),
			"status": result.get("status"),
			"title": result.get("title"),
			"text": result.get("text"),
			"_context": {**context, "ai_query_result": True},
		}
