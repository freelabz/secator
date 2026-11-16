"""AI tool: `add_note`."""
import json
from dataclasses import fields
from datetime import datetime, timezone
from typing import Dict, Generator
from secator.output_types import Ai, Error, FINDING_TYPES
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._findings import _lookup_finding
from secator.ai.tools.base import BaseTool


# target_type -> ordered identity ("dedup key") field names, per core OutputType. This is the
# SAME per-type identity the notes store keys off (the ``compare=True`` non-underscore dataclass
# fields = ``OutputType._compare_key``): a url keys off {url}, a port off {port, ip, state}, a
# vulnerability off {name, id, matched_at}. Those survive a re-scan's _uuid churn, so a note
# re-attaches to the re-found finding. Mirrors the platform notes router's identity derivation.
_NOTE_IDENTITY_FIELDS = {
	cls.get_name(): [f.name for f in fields(cls) if f.compare and not f.name.startswith("_")]
	for cls in FINDING_TYPES
}


def _note_stringify(v) -> str:
	"""Coerce an identity value to the stable string form stored in a note's target_key.

	Finding identity fields can be ints/bools (e.g. ``port``, ``state``); the stored key is a
	string map so a note written here compares byte-for-byte with one posted via the platform
	notes endpoint (which stringifies the same way)."""
	if v is None:
		return ""
	if isinstance(v, bool):
		return "true" if v else "false"
	return str(v)


class AddNote(BaseTool):
	name = "add_note"
	action = "add_note"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "add_note",
			"description": (
				"Attach a NOTE (an append-only annotation) to an EXISTING finding, identified by the `_uuid` "
				"from query_workspace results. Use it to record WHY you reached a conclusion, what you observed, "
				"or what changed on a finding between runs — without modifying the finding itself. The note is "
				"stored separately and keyed to the finding's stable identity, so it stays attached even after a "
				"re-scan. Give a clear `body`; when you are recording that specific fields CHANGED, also pass "
				"`changes` so the delta is structured. For a false-positive / exploited verdict use the dedicated "
				"mark_vuln_* tools instead — a note does not change status."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the finding to annotate (from query_workspace results)."
					},
					"body": {
						"type": "string",
						"description": "The note text (plain English / markdown). Required."
					},
					"changes": {
						"type": "array",
						"description": (
							"Optional structured list of field changes to record alongside the note, one entry per "
							"changed field: {\"field\": \"<name>\", \"old\": <before>, \"new\": <after>}."
						),
						"items": {
							"type": "object",
							"properties": {
								"field": {"type": "string", "description": "The finding field that changed."},
								"old": {"description": "The previous value."},
								"new": {"description": "The new value."}
							},
							"required": ["field"]
						}
					}
				},
				"required": ["_uuid", "body"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Attach an append-only NOTE to an existing finding (any type), identified by ``_uuid``.

		A note is an annotation — a human/agent comment, plus an optional structured ``changes``
		list (field old->new deltas) — stored in a DEDICATED notes store, NEVER on the finding.
		It is keyed by the finding's stable dedup identity (``target_type`` + ``target_key``), not
		its mutable ``_uuid``, so the note survives a re-scan that mints a fresh ``_uuid`` for the
		same finding. Persistence follows the active driver: mongodb/sqlite/json write the note
		locally; the ``api`` driver POSTs it to the platform notes endpoint (author + timestamps
		set server-side there). The finding itself is never modified.
		"""
		context = _get_result_context(action, ctx)
		uuid = str(action.get("_uuid") or "").strip()
		body = str(action.get("body") or "").strip()
		changes = action.get("changes")
		if not uuid:
			yield Error(message="add_note requires the finding `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
			return
		if not body:
			yield Error(message="add_note requires a non-empty `body`.", _context=context)
			return
		if isinstance(changes, str):
			try:
				changes = json.loads(changes)
			except (json.JSONDecodeError, TypeError):
				yield Error(message="add_note `changes` must be valid JSON (a list of {field, old, new} objects).", _context=context)  # noqa: E501
				return
		if changes is not None and (
			not isinstance(changes, list)
			or not all(isinstance(c, dict) and str(c.get("field") or "").strip() for c in changes)
		):
			yield Error(message="add_note `changes` must be a list of {field, old, new} objects (each with a non-empty `field`).", _context=context)  # noqa: E501
			return

		target = _lookup_finding(ctx, uuid)
		if not target:
			yield Error(
				message=(
					f"No finding found with _uuid={uuid} in this workspace. "
					"Re-check the `_uuid` from query_workspace results."
				),
				_context=context,
			)
			return

		target_type = str(target.get("_type") or "").strip()
		id_fields = _NOTE_IDENTITY_FIELDS.get(target_type)
		if not id_fields:
			yield Error(message=f"Cannot attach a note to a '{target_type}' finding (no stable identity).", _context=context)  # noqa: E501
			return
		target_key = {f: _note_stringify(target.get(f)) for f in id_fields}

		note = {
			"target_type": target_type,
			"target_key": target_key,
			"body": body,
			"changes": changes or [],
			"author_id": "ai",
			"author_email": "",
			"created_at": datetime.now(timezone.utc),
			"edited_at": None,
			"_context": {"workspace_id": ctx.context.get("workspace_id", "")},
		}
		engine = ctx.get_query_engine()
		try:
			written = engine.create_note(note)
		except Exception as e:
			yield Error(message=f"add_note failed to persist: {e}", _context=context)
			return
		if not written:
			yield Error(message="add_note could not persist the note (the active driver has no notes store).", _context=context)  # noqa: E501
			return

		label = (
			target.get("name")
			or target.get("url")
			or (target.get("matched_at") if isinstance(target.get("matched_at"), str) else None)
			or uuid
		)
		yield Ai(
			content=f"Note added to {target_type} {label}",
			ai_type="add_note",
			extra_data={"target_type": target_type, "target_key": target_key, "body": body, "changes": changes or []},
			_context=context,
		)
