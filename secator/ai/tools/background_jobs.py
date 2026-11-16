"""AI tools: `check_background_jobs` and `cancel_background_job`.

Companions of the ``background`` flag on run_task / run_workflow / run_shell /
run_subagent (see :mod:`secator.ai.background`). Both are read/control-only on the
ai task's own jobs (no target side effect of their own), hence auto-allowed; the
background calls themselves were approved by the guardrails when they were made.
"""
from secator.ai.tools.base import BaseTool


def _ctx_for(action, ctx):
	from secator.ai.actions import _get_result_context
	return _get_result_context(action, ctx)


def _status_item(job, context):
	"""Model-facing status entry (a plain dict: reported in the tool result, not persisted)."""
	return {"_type": "background_job", **job.to_dict(), "_context": dict(context)}


def _result_item(item, context):
	"""A job item re-surfaced for the model under THIS poll's tool call.

	A plain dict tagged ``ai_query_result`` so the loop collects it for the tool result
	without re-yielding or re-persisting it: the ai task already persisted it when it
	drained the job.
	"""
	d = item.toDict() if hasattr(item, "toDict") else dict(item)
	d["_context"] = {**(d.get("_context") or {}), **context, "ai_query_result": True}
	return d


class CheckBackgroundJobs(BaseTool):
	name = "check_background_jobs"
	action = "check_background_jobs"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "check_background_jobs",
			"description": "Check your background jobs (calls made with background=true, and subagents). Returns "
			               "each job's status and the results it produced SINCE YOUR LAST CHECK (partial results "
			               "while running, the rest once finished; a subagent returns its handback). Pass `wait` "
			               "to block up to that many seconds until one of the jobs finishes, instead of polling "
			               "in a loop. Example: check_background_jobs(job_ids=['bg-1'], wait=120).",
			"parameters": {
				"type": "object",
				"properties": {
					"job_ids": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Job ids to check (e.g. ['bg-1']). Omit to check all jobs."
					},
					"wait": {
						"type": "integer",
						"description": "Optional seconds to wait for one of the jobs to finish before returning "
						               "(capped by the run's background_max_wait). 0 or omitted = return now."
					}
				}
			}
		}
	}

	def run(self, action, ctx):
		from secator.output_types import Error
		context = _ctx_for(action, ctx)
		mgr = getattr(ctx, "background", None)
		if mgr is None:
			yield Error(message="Background jobs are not available in this run.", _context=context)
			return
		try:
			wait = int(action.get("wait") or 0)
		except (TypeError, ValueError):
			wait = 0
		job_ids = action.get("job_ids") or []
		if isinstance(job_ids, str):
			job_ids = [job_ids]
		unknown = [i for i in job_ids if mgr.get(i) is None]
		if unknown:
			yield Error(message=(
				f"Unknown background job(s): {unknown}. Jobs only live as long as the run that started "
				f"them; their persisted findings can be read with query_workspace."), _context=context)
		reports = mgr.poll([i for i in job_ids if i not in unknown] or None, wait=wait) \
			if (not job_ids or len(unknown) < len(job_ids)) else []
		if not reports and not unknown:
			yield {"_type": "background_job", "status": "none", "message": "No background jobs.", "_context": dict(context)}
			return
		for job, items in reports:
			yield _status_item(job, context)
			for item in items:
				yield _result_item(item, context)


class CancelBackgroundJob(BaseTool):
	name = "cancel_background_job"
	action = "cancel_background_job"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "cancel_background_job",
			"description": "Cancel a running background job (e.g. a server you no longer need, or a scan that is "
			               "no longer useful). Results it already produced stay stored. "
			               "Example: cancel_background_job(job_id='bg-2').",
			"parameters": {
				"type": "object",
				"properties": {
					"job_id": {"type": "string", "description": "The job id to cancel (e.g. 'bg-2')."}
				},
				"required": ["job_id"]
			}
		}
	}

	def run(self, action, ctx):
		from secator.output_types import Error
		context = _ctx_for(action, ctx)
		mgr = getattr(ctx, "background", None)
		if mgr is None:
			yield Error(message="Background jobs are not available in this run.", _context=context)
			return
		job_id = action.get("job_id", "")
		job = mgr.cancel(job_id)
		if job is None:
			yield Error(message=f"Unknown background job {job_id!r}.", _context=context)
			return
		yield _status_item(job, context)
