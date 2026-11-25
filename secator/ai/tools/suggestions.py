"""AI tools for runner suggestions, in chat mode only: ``list_suggestions`` (read the
workspace's suggestions) and ``add_suggestion`` (record one).

``add_suggestion`` yields a :class:`Suggestion`, which every driver stores in its own
suggestions store (see the drivers' ``update_finding`` hooks); ``list_suggestions`` reads
that store back through the active query backend.
"""
from typing import Dict, Generator

from secator.output_types import Ai, Error, Info, Suggestion
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA

_RUNNER_TYPES = ("task", "workflow", "scan")
_PRIORITIES = ("low", "medium", "high")
_MAX_LISTED = 50  # most recent suggestions shown to the model
_MAX_LISTED_TARGETS = 20
_NO_DUPLICATE_RULE = (
	"Call list_suggestions first and never add a suggestion that already exists (same type, name "
	"and targets), even when it is done or dismissed."
)


class AddSuggestion(BaseTool):
	name = "add_suggestion"
	action = "add_suggestion"
	auto_allow = True  # records a suggestion only: no target or path side effect
	schema = {
		"type": "function",
		"function": {
			"name": "add_suggestion",
			"description": (
				"Suggest a secator task, workflow or scan to run next on some targets. It is NOT run: "
				"the suggestion is stored for the user to review and launch. Give the real config name, "
				"the targets it should run on, only the options that matter, and a one-sentence reason. "
				+ _NO_DUPLICATE_RULE
			),
			"parameters": {
				"type": "object",
				"properties": {
					"type": {"type": "string", "enum": list(_RUNNER_TYPES), "description": "Runner type."},
					"name": {"type": "string", "description": "Task, workflow or scan config name (e.g. httpx, url_crawl)."},  # noqa: E501
					"targets": _TARGETS_SCHEMA,
					"opts": {"type": "object", "description": "Key run options, if any (e.g. {\"profiles\": [\"passive\"]})."},  # noqa: E501
					"reason": {"type": "string", "description": "Why this is worth running, in one sentence."},
					"priority": {"type": "string", "enum": list(_PRIORITIES), "description": "Default: medium."},
				},
				"required": ["type", "name", "targets", "reason"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Validate the suggested config against the known configs, then yield a Suggestion."""
		from secator.loader import get_configs_by_type
		context = _get_result_context(action, ctx)
		runner_type = str(action.get("type") or "").strip()
		name = str(action.get("name") or "").strip()
		targets = action.get("targets") or []
		targets = [targets] if isinstance(targets, str) else targets
		opts = action.get("opts") or {}
		reason = str(action.get("reason") or "").strip()
		priority = str(action.get("priority") or "medium").strip()
		if runner_type not in _RUNNER_TYPES:
			yield Error(message=f"add_suggestion `type` must be one of {', '.join(_RUNNER_TYPES)}.", _context=context)
			return
		if name not in {c["name"] for c in get_configs_by_type(runner_type)}:
			yield Error(message=f"Unknown {runner_type} '{name}': suggest a real secator {runner_type} name.", _context=context)  # noqa: E501
			return
		if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
			yield Error(message="add_suggestion `targets` must be a list of strings.", _context=context)
			return
		targets = sorted({t.strip() for t in targets} - {""})
		if not targets or not reason:
			yield Error(message="add_suggestion requires non-empty `targets` and `reason`.", _context=context)
			return
		if not isinstance(opts, dict):
			yield Error(message="add_suggestion `opts` must be an object.", _context=context)
			return
		if priority not in _PRIORITIES:
			yield Error(message=f"add_suggestion `priority` must be one of {', '.join(_PRIORITIES)}.", _context=context)
			return
		yield Suggestion(
			name=name, type=runner_type, targets=targets, opts=opts, reason=reason, priority=priority,
			source="ai", _context=context,
		)


def _summary(doc):
	"""One compact row from a stored suggestion: the ``suggestions`` collection shape (``data`` /
	``context``) or a flat :class:`Suggestion` record."""
	if "data" in doc:
		data, context = doc.get("data") or {}, doc.get("context") or {}
		runner_type, name = data.get("type"), data.get("name")
		targets, reason = data.get("targets") or [], doc.get("message")
		status = "dismissed" if context.get("dismissed") else "done" if context.get("done") else "pending"
	else:
		runner_type, name, targets = doc.get("type"), doc.get("name"), doc.get("targets") or []
		reason, status = doc.get("reason"), "pending"
	targets = [targets] if isinstance(targets, str) else targets
	return {
		"type": runner_type, "name": name, "targets": targets[:_MAX_LISTED_TARGETS], "targets_count": len(targets),
		"source": doc.get("source") or "", "status": status, "reason": reason,
	}


class ListSuggestions(BaseTool):
	name = "list_suggestions"
	action = "list_suggestions"
	auto_allow = True  # read-only
	schema = {
		"type": "function",
		"function": {
			"name": "list_suggestions",
			"description": (
				f"List the workspace's existing runner suggestions, most recent first (at most {_MAX_LISTED}): "
				"type, name, targets, source, status (pending / done / dismissed) and reason. "
				"Call it before add_suggestion so you never suggest the same thing twice."
			),
			"parameters": {"type": "object", "properties": {}, "required": []},
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Read the suggestions back through the active query backend; rows go to the model only."""
		context = _get_result_context(action, ctx)
		try:
			docs = ctx.get_query_engine().list_suggestions(_MAX_LISTED + 1)
		except Exception as e:  # never "no suggestions": the model would re-add existing ones
			yield Error(message=f"Failed to list suggestions, do not add any: {e}", _context=context)
			return
		rows = [_summary(doc) for doc in docs[:_MAX_LISTED]]
		yield Ai(
			content="suggestions", ai_type="list_suggestions",
			extra_data={"count": len(rows), "has_more": len(docs) > _MAX_LISTED}, _context=context,
		)
		if not rows:
			yield Info(message="No suggestions yet.", _context=context)
		for row in rows:
			yield {"_type": "suggestion_row", **row, "_context": {**context, "ai_query_result": True}}
