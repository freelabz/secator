"""AI tool: `list_runners`."""
from typing import Dict, Generator
from secator.output_types import Ai, Error, Info, Warning
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool


class ListRunners(BaseTool):
	name = "list_runners"
	action = "list_runners"
	auto_allow = True  # read-only run-history lookup; no mutation, no target/path egress
	schema = {
		"type": "function",
		"function": {
			"name": "list_runners",
			"description": (
				"List the run history of this workspace — the scans / workflows / tasks that have run, "
				"newest first, with their status, targets and timing. Use it to answer questions like "
				"'which scans ran in the last 24h?' or 'what failed recently?'. This lists RUN activity; "
				"use query_workspace for the findings those runs produced."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"runner_type": {
						"type": "string",
						"enum": ["scan", "workflow", "task"],
						"description": "Filter to one runner type (e.g. 'scan'). Omit to list all types."
					},
					"since": {
						"type": "string",
						"description": "Only runners started within this window: a relative age like '24h', '7d', '30m', '2w', or an ISO-8601 date/datetime. Omit for no time filter."  # noqa: E501
					},
					"status": {
						"type": "string",
						"description": "Filter by run status (e.g. 'SUCCESS', 'FAILURE', 'RUNNING'). Omit for any."
					},
					"include_children": {
						"type": "boolean",
						"description": "Include nested child runners (a scan's sub-workflows/tasks). Default false = top-level runs only."  # noqa: E501
					},
					"limit": {
						"type": "integer",
						"description": "Maximum runners to return (default 50).",
						"default": 50
					}
				},
				"required": []
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""List the workspace's runner run-history (scans/workflows/tasks), newest first.

		Read-only observation tool: reads run metadata (status/targets/timing) via
		``QueryEngine.list_runners`` — it does NOT read findings (use query_workspace for those)
		and touches no targets, so it is auto-allowed like query. Results are surfaced to the
		model only (marked ``ai_query_result``); nothing is persisted.
		"""
		from secator.ai.runner_history import filter_runners
		context = _get_result_context(action, ctx)

		runner_type = action.get("runner_type") or None
		if runner_type:
			runner_type = str(runner_type).strip().lower() or None
		since = action.get("since")
		status = action.get("status")
		limit = action.get("limit", 50)
		# Default to outermost runs only (a scan, not its many sub-tasks); include_children opens it up.
		has_parent = None if action.get("include_children") else False

		workspace_id = ctx.context.get("workspace_id", "")
		engine = ctx.get_query_engine()
		is_local = getattr(engine.backend, "name", "") == "json"
		if not is_local and not workspace_id:
			yield Warning(message="No workspace available to list runners", _context=context)
			return

		try:
			runners = engine.list_runners(
				workspace_id=workspace_id or None, runner_type=runner_type, has_parent=has_parent)
		except Exception as e:
			yield Error(message=f"Failed to list runners: {e}", _context=context)
			return

		try:
			summaries = filter_runners(runners, since=since, status=status, limit=limit)
		except ValueError as e:
			yield Error(message=str(e), _context=context)
			return
		# Signal truncation so the model can tell "exactly limit" from "more exist".
		try:
			limit_int = int(limit)
		except (TypeError, ValueError):
			limit_int = 50
		has_more = bool(limit_int > 0 and len(summaries) >= limit_int)
		yield Ai(
			content=(f"{runner_type or 'runner'} history"
			         + (f" since {since}" if since else "")
			         + (f" status={status}" if status else "")),
			ai_type="list_runners",
			extra_data={"runners": summaries, "count": len(summaries), "has_more": has_more,
			            "runner_type": runner_type, "since": since, "status": status},
			_context=context,
		)
		if not summaries:
			yield Info(
				message=("No runners found"
				         + (f" of type {runner_type}" if runner_type else "")
				         + (f" since {since}" if since else "")
				         + (f" with status {status}" if status else "") + "."),
				_context=context,
			)
			return
		for row in summaries:
			row = dict(row)
			row.setdefault("_type", "runner")
			row["_context"] = {**context, "ai_query_result": True}
			yield row
