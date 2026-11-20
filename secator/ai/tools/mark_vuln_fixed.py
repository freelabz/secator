"""AI tool: `mark_vuln_fixed`."""
import time
from typing import Dict, Generator
from secator.output_types import Ai, Error
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._findings import _lookup_finding, _merge_extra_data, _scoped_vuln_update
from secator.ai.tools.base import BaseTool


class MarkVulnFixed(BaseTool):
	name = "mark_vuln_fixed"
	action = "mark_vuln_fixed"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "mark_vuln_fixed",
			"description": (
				"Mark an EXISTING vulnerability as FIXED — a REAL vulnerability (typically one previously "
				"confirmed EXPLOITED) that no longer reproduces because it has been remediated/patched. "
				"Identify it by the `_uuid` from query_workspace results. Sets status='FIXED' but keeps the vuln "
				"VISIBLE (does NOT hide it) — it is a resolved part of the history, not a false positive. Use this "
				"(NOT mark_vuln_false_positive) when the vuln WAS genuine but is now gone/closed. Give a short "
				"`reason` (what changed). Prefer pairing it with an `add_note` recording the evidence that it is gone."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark fixed (from query_workspace results)."
					},
					"reason": {
						"type": "string",
						"description": "Short reason it's now fixed (e.g. 'patched to 1.2.4', 'endpoint removed'). Recorded on the vuln."  # noqa: E501
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
		"""Mark an EXISTING vulnerability as FIXED — a genuine vuln (often previously EXPLOITED) that no
		longer reproduces because it was remediated. Sets ``status="FIXED"`` via a scoped ``$set`` matched
		by ``_uuid`` and keeps the finding VISIBLE (``is_false_positive`` is left untouched): a fixed vuln
		is resolved history, not a false positive. Unlike the exploited/failed verdicts this records NO
		exploit attempt and does NOT run the attempt rollup — FIXED is a terminal remediation status, not
		an exploitation outcome. An optional ``reason`` is stored in ``extra_data.fixed_reason``.
		"""
		context = _get_result_context(action, ctx)
		uuid = str(action.get("_uuid") or "").strip()
		if not uuid:
			yield Error(message="mark_vuln_fixed requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
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

		# FIXED is set directly (no is_false_positive change → stays visible). verified=False: it is no
		# longer a live/exploitable finding.
		# fixed_at is the remediation boundary the attempt rollup honours: only a success recorded
		# after it can re-open the vuln as EXPLOITED.
		update = {"status": "FIXED", "verified": False, "extra_data.fixed_at": time.time()}
		if reason:
			update["extra_data.fixed_reason"] = reason
		_merge_extra_data(update, action.get("extra_data"))

		try:
			modified, updated, label, err = _scoped_vuln_update(ctx, uuid, update)
		except Exception as e:
			yield Error(message=f"Failed to mark vulnerability fixed: {e}", _context=context)
			return
		if err:
			yield Error(message=err, _context=context)
			return
		msg = f"Marked {label} as fixed" + (f" ({reason})." if reason else ".")
		yield Ai(
			content=msg,
			ai_type="mark_vuln_fixed",
			extra_data={"finding": updated} if updated else {},
			_context=context,
		)
