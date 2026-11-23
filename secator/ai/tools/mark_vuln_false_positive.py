"""AI tool: `mark_vuln_false_positive`."""
from typing import Dict, Generator
from secator.output_types import Ai, Error
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._findings import (
	_attempt_counts, _build_exploit_attempt, _lookup_finding, _merge_extra_data, _scoped_vuln_update,
)
from secator.ai.tools.base import BaseTool


class MarkVulnFalsePositive(BaseTool):
	name = "mark_vuln_false_positive"
	action = "mark_vuln_false_positive"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "mark_vuln_false_positive",
			"description": (
				"Mark an EXISTING vulnerability as a false positive when you determined it could NOT be "
				"exploited (scanner false positive, not reachable, already patched). Identify it by the `_uuid` "
				"from query_workspace results. The vuln is hidden from reports (is_false_positive=true, "
				"status='FALSE_POSITIVE') but KEPT and recoverable — never deleted. Give a short `reason`."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark false positive (from query_workspace results)."
					},
					"reason": {
						"type": "string",
						"description": "Short reason why it's a false positive (e.g. 'not reachable', 'patched'). Recorded on the vuln."  # noqa: E501
					},
					"extra_data": {
						"type": "object",
						"description": "Extra structured context merged into the vuln (existing keys preserved). Optional.",
						"additionalProperties": True
					}
				},
				"required": ["_uuid"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Mark an EXISTING vulnerability as a false positive.

		Sets ``is_false_positive=True`` (the authoritative hide-flag the store base query
		filters on EVERY backend, so the finding disappears from all reads/reports),
		``status=FALSE_POSITIVE`` and ``verified=False`` via a scoped ``$set`` matched by the
		``_uuid`` from ``query_workspace``. Non-destructive: the finding is kept and stays
		recoverable (unset ``is_false_positive``). An optional ``reason`` is stored in
		``extra_data.false_positive_reason``.
		"""
		context = _get_result_context(action, ctx)
		uuid = str(action.get("_uuid") or "").strip()
		if not uuid:
			yield Error(message="mark_vuln_false_positive requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
			return
		reason = str(action.get("reason") or "").strip()
		if ctx.encryptor and reason:
			reason = _decrypt_dict({"reason": reason}, ctx.encryptor).get("reason", reason)

		vuln = _lookup_finding(ctx, uuid)
		if not vuln or vuln.get("_type") != "vulnerability":
			yield Error(
				message=f"No vulnerability found with _uuid={uuid} in this workspace. "
				"Re-check the `_uuid` from query_workspace results.", _context=context)
			return

		# Record the false-positive determination as an append-only attempt, so the vuln's exploit
		# history shows the FP outcome alongside the success/failed attempts.
		attempt = _build_exploit_attempt(ctx, context, vuln, "false_positive", action, reason=reason)
		yield attempt

		# Recap counts across ALL attempts (including this FP, which may not be queryable yet).
		engine = ctx.get_query_engine()
		persisted = engine.search(
			{"_type": "exploit_attempt", "vuln_name": vuln.get("name", ""),
			 "vuln_id": vuln.get("id", ""), "matched_at": vuln.get("matched_at", "")}, scope_only=True) or []
		pd = attempt.toDict()
		if not (pd.get("_uuid") and any(a.get("_uuid") == pd.get("_uuid") for a in persisted)):
			persisted = persisted + [pd]

		# FP owns is_false_positive + status directly (NOT the exploited/failed rollup — a FP must not
		# be re-derived as EXPLOITED/EXPLOIT FAILED). Just denormalize the recap alongside the verdict.
		update = {
			"is_false_positive": True, "status": "FALSE_POSITIVE", "verified": False,
			"extra_data.exploit_attempts": _attempt_counts(persisted),
		}
		if reason:
			update["extra_data.false_positive_reason"] = reason
		_merge_extra_data(update, action.get("extra_data"))

		try:
			modified, updated, label, err = _scoped_vuln_update(ctx, uuid, update, doc=vuln)
		except Exception as e:
			yield Error(message=f"Failed to mark vulnerability false positive: {e}", _context=context)
			return
		if err:
			yield Error(message=err, _context=context)
			return
		msg = f"Marked {label} as a false positive" + (f" ({reason})." if reason else ".")
		yield Ai(
			content=msg,
			ai_type="mark_vuln_false_positive",
			extra_data={"finding": updated, "attempt": attempt.toDict()} if updated else {"attempt": attempt.toDict()},
			_context=context,
		)
