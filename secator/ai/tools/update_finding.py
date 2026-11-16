"""AI tool: `update_finding`."""
import json
from typing import Dict, Generator
from secator.output_types import Ai, Error, FINDING_TYPES
from secator.ai.utils import _coerce_finding_fields, _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._findings import (
	_FINDING_IMMUTABLE_FIELDS, _SERVER_OWNED_EXTRA_DATA, _drop_readonly_fields, _lookup_finding,
)
from secator.ai.tools.base import BaseTool


# Real scan-finding types (vulnerability/url/port/…) update_finding may edit. Restricting to
# these stops a known `_uuid` from editing a non-finding record: error/warning/info (EXECUTION_TYPES)
# and stat (STAT_TYPES) aren't in FINDING_TYPES already, and `ai` IS in FINDING_TYPES but is the
# conversation/action-doc type — editing it would tamper the transcript, so exclude it.
_FINDING_TYPE_NAMES = frozenset(cls.get_name().lower() for cls in FINDING_TYPES) - {"ai"}


def _coerce_bool(value):
	"""Parse a boolean from the LLM's loosely-typed ``fields`` value. Accepts a real bool, 0/1,
	or a common boolean string (true/false/1/0/yes/no, case-insensitive); returns None for
	anything else so the caller rejects it — NOT ``bool(value)``, which treats the string
	``"false"`` as True and would hide a real finding."""
	if isinstance(value, bool):
		return value
	if isinstance(value, (int, float)) and value in (0, 1):
		return bool(value)
	if isinstance(value, str):
		v = value.strip().lower()
		if v in ("true", "1", "yes", "y", "on"):
			return True
		if v in ("false", "0", "no", "n", "off"):
			return False
	return None


class UpdateFinding(BaseTool):
	name = "update_finding"
	action = "update_finding"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "update_finding",
			"description": (
				"Update fields on an EXISTING finding (any type) identified by the `_uuid` you saw in "
				"query_workspace results — e.g. fix a severity, add tags/cves, or enrich extra_data. Only the "
				"fields you pass are changed; everything else is left intact. For a vulnerability's exploited "
				"or false-positive verdict, use mark_vuln_exploited / mark_vuln_false_positive instead."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the finding to update (from query_workspace results)."
					},
					"fields": {
						"type": "object",
						"description": (
							"Top-level finding fields to set (e.g. {\"severity\": \"high\", \"tags\": [\"xss\"]}). "
							"Immutable keys (_uuid, _type, _id, _context, id) are ignored. List fields must be JSON arrays."
						),
						"additionalProperties": True
					},
					"extra_data": {
						"type": "object",
						"description": "Structured context merged into the finding's extra_data (existing keys preserved).",
						"additionalProperties": True
					}
				},
				"required": ["_uuid"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Set fields on an EXISTING finding (any type) identified by ``_uuid``.

		A workspace-scoped ``$set`` touching only the caller-named fields — immutable
		identity/routing keys are stripped, and mutating a ``target`` finding is refused so the
		AI can't widen scope. Used to fix a wrong field (e.g. severity), add tags/cves, or enrich
		extra_data. For a vulnerability's exploited / false-positive verdict, prefer the dedicated
		``mark_vuln_exploited`` / ``mark_vuln_false_positive`` tools.
		"""
		context = _get_result_context(action, ctx)
		uuid = str(action.get("_uuid") or "").strip()
		if not uuid:
			yield Error(message="update_finding requires the finding `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
			return

		fields = action.get("fields") or {}
		extra_data = action.get("extra_data") or {}
		if isinstance(fields, str):
			try:
				fields = json.loads(fields)
			except (json.JSONDecodeError, TypeError):
				fields = {}
		if isinstance(extra_data, str):
			try:
				extra_data = json.loads(extra_data)
			except (json.JSONDecodeError, TypeError):
				extra_data = {}
		if not isinstance(fields, dict) or not isinstance(extra_data, dict):
			yield Error(message="update_finding `fields` and `extra_data` must be JSON objects.", _context=context)
			return
		if ctx.encryptor:
			fields = _decrypt_dict(fields, ctx.encryptor)
			extra_data = _decrypt_dict(extra_data, ctx.encryptor)

		existing = _lookup_finding(ctx, uuid)
		if not existing:
			yield Error(
				message=f"No finding found with _uuid={uuid} in this workspace. Re-check the `_uuid` from query_workspace results.",  # noqa: E501
				_context=context,
			)
			return
		etype = str(existing.get("_type", "")).lower()
		if etype == "target":
			yield Error(message="Refusing to update a 'target' finding (scope integrity).", _context=context)
			return
		if etype == "exploit_attempt":
			# Append-only history: editing an attempt's evidence (poc/vuln_name/vuln_id/matched_at/verdict)
			# would rewrite the record a vuln's status is derived from. Record a NEW attempt instead.
			yield Error(
				message="Refusing to update an 'exploit_attempt' — attempts are append-only history. Record a "
				"new attempt via mark_vuln_exploited / mark_vuln_exploit_failed.", _context=context)
			return
		if etype not in _FINDING_TYPE_NAMES:
			yield Error(message=f"Refusing to update a non-finding record (_type={etype!r}).", _context=context)
			return
		cls = {c.get_name().lower(): c for c in FINDING_TYPES}[etype]
		cls_fields = set(getattr(cls, "__dataclass_fields__", {}))

		# Attack-surface cleanup verdict (any finding type, not just vulns): the recoverable
		# hide-flag `is_false_positive` is normally server-owned (stripped by _drop_readonly_fields
		# so an agent can't forge the verified/exploited verdict). We allow ONLY this one flag here,
		# server-DERIVED — never `verified`/`status=EXPLOITED` — so a cleanup pass can retire a
		# finding (subdomain/ip/port/…) that no longer reproduces. It stays recoverable (set back
		# to False), and the caller stamps an auditable reason in extra_data for bulk reversal.
		# For a VULNERABILITY the hide verdict belongs to the dedicated mark_vuln_false_positive
		# tool (its reason/refetch handling + the vuln gate), so is_false_positive stays stripped
		# here. For every other attack-surface type there is no dedicated tool, so this is the path.
		verdict = {}
		if etype != "vulnerability" and "is_false_positive" in fields:
			if "is_false_positive" not in cls_fields:
				yield Error(message=f"{etype} findings have no is_false_positive field; downgrade its `confidence` instead or leave it.", _context=context)  # noqa: E501
				return
			fp = _coerce_bool(fields.pop("is_false_positive"))
			if fp is None:
				yield Error(message="is_false_positive must be a boolean (true or false).", _context=context)
				return
			verdict["is_false_positive"] = fp
			# Do NOT write `status` here. For the non-vulnerability types this path handles, `status`
			# is a DATA field (e.g. Domain's WHOIS-observation list, a certificate's validity state) —
			# writing "FALSE_POSITIVE" would clobber real data. The hide is driven solely by
			# `is_false_positive`; a vulnerability's verdict `status` is owned by
			# mark_vuln_false_positive, and vulns never reach this branch.
			if fp and "verified" in cls_fields:
				verdict["verified"] = False

		# Only agent-writable content fields (framework/server-owned + `*_path` stripped); `id`
		# stays blocked on UPDATE via _FINDING_IMMUTABLE_FIELDS below.
		# Remember what the model asked to set (minus operators) BEFORE we strip readonly/immutable
		# fields, so that if nothing survives we can tell it WHICH fields were rejected and where to
		# set them instead — rather than the misleading "pass fields" (it did pass fields).
		requested_field_keys = {str(k) for k in fields if not str(k).startswith("$")}
		fields = _drop_readonly_fields(fields)
		# An `extra_data` object passed INSIDE `fields` must merge via dotted keys (like the dedicated
		# `extra_data` arg) — a whole-object $set would clobber existing keys AND conflict with the
		# dotted `extra_data.*` paths on Mongo. Fold it into extra_data (the dedicated arg wins).
		fields_extra = fields.pop("extra_data", None)
		if isinstance(fields_extra, dict):
			extra_data = {**fields_extra, **extra_data}
		# Validate the remaining content fields against the finding's schema (coerce sloppy scalars
		# first, like add_finding) so a wrong-shaped value (e.g. tags="xss" where a list is required)
		# is rejected up front, not persisted raw.
		fields = _coerce_finding_fields(cls, fields)
		errors = cls.validate_fields(fields)
		if errors:
			yield Error(message=f"Invalid {etype} fields: {'; '.join(errors)}", _context=context)
			return

		update = {}
		for k, v in fields.items():
			key = str(k)
			if key in _FINDING_IMMUTABLE_FIELDS or key.startswith("$") or "." in key:
				continue
			update[key] = v
		for k, v in extra_data.items():
			key = str(k)
			if key and "." not in key and not key.startswith("$") and key not in _SERVER_OWNED_EXTRA_DATA:
				update[f"extra_data.{key}"] = v
		# A confidence downgrade must re-prioritize: recompute the derived sort key where the type
		# carries it (update_finding writes a raw $set, so __post_init__ never runs to derive it).
		if "confidence" in update and "confidence_nb" in cls_fields:
			cn = {"high": 1, "medium": 2, "low": 3}.get(str(update["confidence"]).lower())
			if cn:
				update["confidence_nb"] = cn
		# Server-derived verdict last so it wins over any stale free-form copy.
		update.update(verdict)
		if not update:
			blocked = sorted(requested_field_keys - set(update))
			if blocked:
				# The model DID pass fields, but every one was read-only/verdict/immutable and got
				# dropped. Name them and point at the right tool so it stops retrying the same call.
				yield Error(
					message=(
						f"update_finding: none of {blocked} can be set here. Verdict fields "
						"(verified/status/is_false_positive) are set via mark_vuln_exploited / "
						"mark_vuln_false_positive / mark_vuln_exploit_failed; confidence_nb/severity_nb are "
						"server-derived; *_path and framework (_-prefixed) fields are read-only. Pass editable "
						"content (e.g. name, description, severity) or notes under `extra_data` instead."
					),
					_context=context,
				)
			else:
				yield Error(message="update_finding: nothing to update (pass `fields` and/or `extra_data`).", _context=context)  # noqa: E501
			return

		engine = ctx.get_query_engine()
		try:
			modified = engine.update({"_uuid": uuid}, {"$set": update})
		except Exception as e:
			yield Error(message=f"Failed to update finding: {e}", _context=context)
			return
		if not modified:
			yield Error(message=f"No finding updated for _uuid={uuid}.", _context=context)
			return

		updated = _lookup_finding(ctx, uuid)
		if updated:
			from secator.query.json import _apply_set
			_apply_set(updated, update)
		yield Ai(
			content=f"Updated finding {uuid} ({', '.join(sorted(update.keys()))}).",
			ai_type="update_finding",
			extra_data={"finding": updated} if updated else {},
			_context=context,
		)
