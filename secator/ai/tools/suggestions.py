"""AI tool that records a runner suggestion: ``add_suggestion``.

Not in any mode's baseline (``external = True``): a caller grants it to a run through the
``ai`` task's ``extra_tools`` option. The tool yields a :class:`Suggestion`, which every
driver stores in its own suggestions store (see the drivers' ``update_finding`` hooks).
"""
from typing import Dict, Generator

from secator.output_types import Error, Suggestion
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool, _TARGETS_SCHEMA

_RUNNER_TYPES = ("task", "workflow", "scan")
_PRIORITIES = ("low", "medium", "high")


class AddSuggestion(BaseTool):
	name = "add_suggestion"
	action = "add_suggestion"
	auto_allow = True  # records a suggestion only: no target or path side effect
	external = True  # never in a mode's baseline; granted per run through extra_tools
	schema = {
		"type": "function",
		"function": {
			"name": "add_suggestion",
			"description": (
				"Suggest a secator task, workflow or scan to run next on some targets. It is NOT run: "
				"the suggestion is stored for the user to review and launch. Give the real config name, "
				"the targets it should run on, only the options that matter, and a one-sentence reason."
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
