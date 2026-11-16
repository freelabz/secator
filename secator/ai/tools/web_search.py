"""AI tool: `web_search`."""
from typing import Dict, Generator
from secator.output_types import Ai, Error, Info
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool


class WebSearch(BaseTool):
	name = "web_search"
	action = "web_search"
	auto_allow = True  # read-only external lookup; no workspace mutation, no target scope
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

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Search the public web for external context (CVE write-ups, PoCs, tool docs).

		Read-only and target-agnostic: it hits public search engines, not the engagement
		targets, so it is NOT gated by target/scope guardrails (see guardrails auto-allow).
		Results are surfaced to the model only (marked ``ai_query_result``) — they are not
		persisted as workspace findings. Fails soft: an engine error yields a clean note,
		never an exception that aborts the AI loop.
		"""
		from secator.ai.web_search import web_search, VALID_MODES
		context = _get_result_context(action, ctx)

		query = action.get("query", "")
		if ctx.encryptor and isinstance(query, str):
			query = _decrypt_dict({"query": query}, ctx.encryptor).get("query", query)
		query = str(query or "").strip()
		if not query:
			yield Error(message="web_search requires a non-empty `query`.", _context=context)
			return

		mode = str(action.get("mode") or "answer").lower()
		if mode not in VALID_MODES:
			mode = "answer"
		max_results = action.get("max_results", 5)
		exploit_type = str(action.get("exploit_type") or "exploits").lower()
		sort = str(action.get("sort") or "default").lower()

		results, engine = web_search(
			query, mode=mode, max_results=max_results, exploit_type=exploit_type, sort=sort)

		yield Ai(
			content=query,
			ai_type="web_search",
			extra_data={"results": results, "count": len(results), "mode": mode, "engine": engine},
			_context=context,
		)
		if not results:
			# Surface an explicit "no results" to the model (mode/engine included) so it can
			# reword the query or switch mode rather than assume the tool is broken.
			yield Info(
				message=f"web_search ({mode} via {engine}) returned no results for {query!r}.",
				_context=context,
			)
			return
		# Surface each hit to the model as an observation-only result (like query_workspace):
		# marked ai_query_result so the runner neither persists nor re-yields it as a finding.
		for hit in results:
			hit = dict(hit)
			hit["_context"] = {**context, "ai_query_result": True}
			yield hit
