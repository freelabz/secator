"""Shared helpers for the finding-curation tools (add_finding / update_finding / add_note /
mark_vuln_*): scoped finding lookup + update, exploit-attempt records and the vuln rollup.

Moved verbatim from ``secator/ai/actions.py``.
"""
import copy
import threading
from typing import Dict, Optional
from secator.output_types import ExploitAttempt, OutputType
from secator.utils import debug
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext


def _run_item_update_hooks(ctx: ActionContext, item, phase: str):
	"""Run the ``on_item_update`` hooks of ``phase`` on ``item``; a failure never fails the caller."""
	if not ctx.run_item_update_hooks or item is None:
		return item
	try:
		result = ctx.run_item_update_hooks(item, phase=phase)
	except Exception as e:  # noqa: BLE001 - hooks are best-effort here, the store write is authoritative
		debug(f"on_item_update {phase} hooks failed: {e}", sub="ai")
		return item
	return result if isinstance(result, OutputType) else item


def _changed_fields(new: Dict, old: Dict) -> Dict:
	"""``$set`` fields turning ``old`` into ``new``. A dict that only gained / changed keys is diffed
	as dotted ``field.key`` paths, so concurrent writes to its other keys survive."""
	changed = {}
	for k, v in new.items():
		prev = old.get(k)
		if v == prev:
			continue
		if isinstance(v, dict) and isinstance(prev, dict) and prev.keys() <= v.keys():
			changed.update({f"{k}.{sk}": sv for sk, sv in v.items() if sk not in prev or prev[sk] != sv})
		else:
			changed[k] = v
	return changed


def _apply_finding_update(ctx: ActionContext, query: Dict, update: Dict, doc: Optional[Dict] = None):
	"""Apply a ``$set`` to the finding matched by ``query``, running the ``on_item_update`` hooks.

	The finding is rebuilt from its stored ``doc`` with ``update`` applied (so ``__post_init__``
	recomputes derived fields, e.g. ``severity_nb``), then pre-phase hooks run (they may mutate
	it), then ONE ``engine.update`` writes ``update`` plus every field the rebuild or the hooks
	changed, then post-phase hooks run on the persisted item.

	Returns ``(modified, doc)``: the modified docs count and the updated doc (None if no match).
	"""
	from secator.output_types._base import load_output_types
	from secator.query.json import _apply_set
	engine = ctx.get_query_engine()
	if doc is None:
		doc = (engine.search(query, limit=1, scope_only=True) or [None])[0]
	if doc is None:
		return 0, None
	patched = copy.deepcopy(doc)
	_apply_set(patched, update)
	try:
		item = next(load_output_types([copy.deepcopy(patched)]), None)
	except Exception as e:  # noqa: BLE001 - an unloadable doc still gets the requested $set
		debug(f"could not rebuild finding from {query}: {e}", sub="ai")
		item = None
	set_fields = dict(update)
	if item is not None:
		rebuilt = copy.deepcopy(item.toDict())
		item = _run_item_update_hooks(ctx, item, "pre")
		hooked = item.toDict()
		set_fields.update(_changed_fields({k: v for k, v in rebuilt.items() if k in patched}, patched))
		set_fields.update(_changed_fields(hooked, rebuilt))
	set_fields = {
		k: v for k, v in set_fields.items()
		if k not in _FINDING_IMMUTABLE_FIELDS and k.split(".", 1)[0] not in _FINDING_IMMUTABLE_FIELDS
	}
	# A whole-object $set (e.g. a hook dropped an extra_data key) supersedes its dotted sub-keys
	# (Mongo rejects both in one $set); the object already carries them.
	set_fields = {k: v for k, v in set_fields.items() if "." not in k or k.split(".", 1)[0] not in set_fields}
	modified = engine.update(query, {"$set": set_fields})
	if not modified:
		return 0, None
	_apply_set(patched, set_fields)
	_run_item_update_hooks(ctx, item, "post")
	return modified, patched


def _scoped_vuln_update(ctx: ActionContext, uuid: str, update: Dict, doc: Optional[Dict] = None):
	"""Apply a workspace-scoped ``$set`` to the vulnerability with this ``_uuid``.

	Returns ``(modified, updated, label, error_msg)``: ``modified`` docs count,
	the updated vuln (dict, or None), a display ``label`` (the vuln's ``name``,
	falling back to the uuid), and an ``error_msg`` string when nothing matched.

	Uses ``QueryEngine.update`` (an in-place ``$set`` on the matched doc, via
	``_apply_finding_update``) rather than re-yielding the finding, so it works uniformly
	across backends without risking a duplicate insert. On the mongodb driver a ``_uuid``
	lookup/update is a native ``_id`` index seek (the query layer rewrites a valid-ObjectId
	``_uuid`` to ``_id`` — findings carry ``_uuid = str(_id)``), so these are point operations,
	not workspace scans. The lookup is ``scope_only``: a false-positive vuln is hidden by the
	``is_false_positive:{$ne:True}`` display filter but must still be reachable here.

	Pass ``doc`` (the vuln as just read by the caller) to skip that lookup; leave it None when
	the vuln may have been written since the caller read it (e.g. by the exploit-attempt rollup).
	"""
	query = {"_type": "vulnerability", "_uuid": uuid}
	modified, updated = _apply_finding_update(ctx, query, update, doc=doc)
	if not modified:
		return 0, None, uuid, (
			f"No vulnerability found with _uuid={uuid} in this workspace. "
			"Re-check the `_uuid` from query_workspace results."
		)
	return modified, updated, updated.get("name") or uuid, None


def _merge_extra_data(update: Dict, extra_data) -> None:
	"""Merge caller ``extra_data`` into ``update`` with dotted keys so existing keys survive."""
	if isinstance(extra_data, dict):
		for k, v in extra_data.items():
			key = str(k)
			if key and "." not in key and not key.startswith("$"):
				update[f"extra_data.{key}"] = v


# Per-vulnerability-identity locks so the rollup read-modify-write (read the attempt set -> derive
# -> $set all occurrences) is serialized WITHIN this worker. Actions in a batch run on a thread pool
# (_run_batch), so without this a failed-attempt rollup could read before a concurrent success is
# recorded and then write a stale "EXPLOIT FAILED" over the "EXPLOITED". Cross-worker races are rare
# (different agents usually target different vulns) and self-heal on the next attempt — the
# append-only attempts are never lost, so the denormalized verdict re-converges.
_ROLLUP_LOCKS: Dict = {}


_ROLLUP_LOCKS_GUARD = threading.Lock()


def _rollup_lock(key):
	with _ROLLUP_LOCKS_GUARD:
		lk = _ROLLUP_LOCKS.get(key)
		if lk is None:
			lk = threading.Lock()
			_ROLLUP_LOCKS[key] = lk
		return lk


def _attempt_counts(attempts) -> Dict:
	"""Verdict recap for a vuln's ``extra_data.exploit_attempts`` summary."""
	verdicts = [str(a.get("verdict") or "").lower() for a in attempts]
	return {
		"success": verdicts.count("success"),
		"failed": verdicts.count("failed"),
		"partial": verdicts.count("partial"),
		"false_positive": verdicts.count("false_positive"),
	}


def _recompute_vuln_rollup(ctx: ActionContext, vuln_name: str, vuln_id: str, matched_at: str, pending=None):
	"""Recompute a vulnerability's DERIVED verdict/poc from the SET of its ExploitAttempts.

	Append-only attempts are the source of truth; the vuln's ``status``/``verified``/``poc`` are
	derived from them with SUCCESS STICKY precedence (EXPLOITED > EXPLOIT FAILED > none), so a late
	failure can never clobber an earlier success. A vuln ALREADY marked ``EXPLOITED`` (a legacy
	success from the pre-ExploitAttempt model, or before the backfill runs) is likewise never
	downgraded by a failed attempt. Also denormalizes a recap count
	(``extra_data.exploit_attempts = {success, failed, partial}``). Applied to EVERY occurrence of the
	vuln identity (``name`` + ``id`` + ``matched_at``) so duplicates stay consistent. NEVER touches
	``is_false_positive`` (owned by mark_vuln_false_positive). The whole read-and-update is serialized
	per identity (see ``_rollup_lock``). Returns the primary re-fetched vuln dict (or None).
	Pure Python — no LLM judgment.
	"""
	engine = ctx.get_query_engine()
	vuln_q = {"_type": "vulnerability", "name": vuln_name, "id": vuln_id, "matched_at": matched_at}
	with _rollup_lock((vuln_name, vuln_id, matched_at)):
		attempts = engine.search(
			{"_type": "exploit_attempt", "vuln_name": vuln_name, "vuln_id": vuln_id, "matched_at": matched_at},
			scope_only=True,
		) or []
		# The attempt just yielded by the handler may not be queryable yet (driver write timing), so
		# fold it in explicitly — deduped by _uuid (add_result stamps it on the same object instance).
		if pending is not None:
			pd = pending.toDict() if hasattr(pending, "toDict") else pending
			pu = pd.get("_uuid")
			if not (pu and any(a.get("_uuid") == pu for a in attempts)):
				attempts = attempts + [pd]
		occurrences = engine.search(vuln_q, scope_only=True) or []
		if not attempts:
			return next((v for v in occurrences if not v.get("_duplicate")), occurrences[0] if occurrences else None)
		counts = _attempt_counts(attempts)
		# Current (possibly legacy) vuln state, so a failed attempt never downgrades an EXPLOITED vuln.
		cur = next((v for v in occurrences if not v.get("_duplicate")), occurrences[0] if occurrences else {})
		if counts["success"]:
			successes = [a for a in attempts if str(a.get("verdict") or "").lower() == "success"]
			status, verified = "EXPLOITED", True
			poc = max(successes, key=lambda a: a.get("_timestamp") or 0).get("poc") or ""
		elif (cur or {}).get("status") == "EXPLOITED":
			# Legacy / pre-backfill success — preserve it (keep the existing poc); do not downgrade.
			status, verified, poc = "EXPLOITED", True, (cur or {}).get("poc") or ""
		elif counts["failed"] or counts["partial"]:
			status, verified, poc = "EXPLOIT FAILED", False, ""
		else:
			return cur or None
		update = {"status": status, "verified": verified, "poc": poc, "extra_data.exploit_attempts": counts}
		# engine.update is update_one, so apply the $set to each occurrence by its own _uuid (point ops).
		primary = None
		for v in occurrences:
			vu = v.get("_uuid")
			if not vu:
				continue
			_, v = _apply_finding_update(ctx, {"_type": "vulnerability", "_uuid": vu}, update, doc=v)
			if v and (primary is None or not v.get("_duplicate")):
				primary = v
		return primary


def _build_exploit_attempt(ctx: ActionContext, context: Dict, vuln: Dict, verdict: str, action: Dict,
                           poc: str = "", reason: str = "") -> ExploitAttempt:
	"""Build an ExploitAttempt linked to ``vuln`` by IDENTITY (name+id+matched_at)."""
	fields_in = {
		"technique": action.get("technique") or "",
		"tool": action.get("tool") or "",
		"command": action.get("command") or "",
		"payload": action.get("payload") or "",
		"evidence": action.get("evidence") or "",
	}
	if ctx.encryptor:
		fields_in = _decrypt_dict(fields_in, ctx.encryptor)
	name = str(action.get("name") or vuln.get("name") or "exploit attempt").strip()
	return ExploitAttempt(
		name=name,
		verdict=verdict,
		vuln_name=vuln.get("name", "") or "",
		vuln_id=vuln.get("id", "") or "",
		matched_at=vuln.get("matched_at", "") or "",
		vulnerability_uuid=vuln.get("_uuid", "") or "",
		technique=fields_in.get("technique", ""),
		tool=fields_in.get("tool", ""),
		command=fields_in.get("command", ""),
		payload=fields_in.get("payload", ""),
		evidence=fields_in.get("evidence", ""),
		poc=poc,
		reason=reason,
		session_id=context.get("session_id") or ctx.session_id or "",
		agent=ctx.model or "",
		_context=context,
	)


# Fields that must never be overwritten via update_finding (identity / routing / scope).
_FINDING_IMMUTABLE_FIELDS = {"_uuid", "_type", "_id", "_context", "id"}


# Server/pipeline-owned finding fields the GENERIC add_finding/update_finding must never let the
# agent write. The dedicated mark_vuln_* tools set the verdict fields themselves via a server-built
# `$set`, so they are unaffected — only the free-form tools are restricted.
_AGENT_READONLY_FIELDS = frozenset({
	"workspace_id",                                                 # scope lives on _context, never top-level
	"verified", "status", "is_false_positive", "is_acknowledged",   # verdict — forging bypasses mark_vuln_* gates
	"verdict",                                                      # exploit-attempt result — mark_vuln_* + rollup only
	"confidence_nb", "severity_nb",                                 # server-derived in __post_init__
})


def _drop_readonly_fields(data: Dict) -> Dict:
	"""Strip fields an LLM-supplied finding write must not set.

	SECURITY: these tools write STRAIGHT to the store on the worker, bypassing the API's ingest
	guards, so a prompt-injected agent must not reach:
	- ``*_path`` — worker-filesystem paths streamed back by the finding-storage endpoint
	  (authenticated arbitrary-file-read / foreign-blob read);
	- any ``_``-prefixed framework field — identity/scope (``_uuid``/``_context``/``_id``),
	  provenance (``_source``/``_timestamp``), dedup (``_tagged``/``_duplicate``/``_related``),
	  the notification flag (``_email_notified``), etc.;
	- verdict/derived fields (``_AGENT_READONLY_FIELDS``) — forging ``verified``/``status``/
	  ``is_false_positive`` bypasses the dedicated tools' gates (e.g. mark_vuln_exploited's
	  mandatory PoC); ``confidence_nb``/``severity_nb`` are recomputed by the server.
	Deny-by-default on the framework (``_`` prefix) keeps future ``_``-fields safe automatically.
	"""
	return {
		k: v for k, v in data.items()
		if not str(k).startswith("_")
		and not str(k).endswith("_path")
		and k not in _AGENT_READONLY_FIELDS
	}


def _lookup_finding(ctx: "ActionContext", uuid: str):
	"""Return the workspace finding with this ``_uuid`` (dict), or None.

	A targeted by-``_uuid`` read uses ``scope_only=True`` so it reaches the finding
	regardless of its display state — a finding already marked ``is_false_positive`` (or
	otherwise hidden by the base display filter) must still be found by its uuid so the
	verdict/annotation/monitor handlers can act on it (e.g. un-hide it, or re-validate a
	previously-hidden finding). Still workspace-scoped, so it never crosses into another
	workspace or reaches an already-removed doc."""
	engine = ctx.get_query_engine()
	return (engine.search({"_uuid": uuid}, limit=1, scope_only=True) or [None])[0]
