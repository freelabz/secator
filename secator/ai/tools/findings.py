"""AI tools that read and curate workspace findings.

* ``query_workspace`` — read stored findings (MongoDB-style query).
* ``add_finding`` / ``update_finding`` — create / edit a finding.
* ``mark_vuln_exploited`` / ``mark_vuln_exploit_failed`` / ``mark_vuln_false_positive`` /
``mark_vuln_fixed`` — record a verdict on a vulnerability (exploit attempts + rollup).
* ``add_note`` — attach a note to a finding.

The shared helpers at the top (scoped finding lookup + update, exploit-attempt records and
the vuln rollup) are used only by these tools.
"""
import threading
import json
from typing import Dict, Generator, Optional
from dataclasses import fields
from datetime import datetime, timezone
from secator.output_types import ExploitAttempt, Ai, Error, Info, OutputType, Warning, FINDING_TYPES
from secator.ai.utils import _decrypt_dict, _union_live_results, loads_lenient, _coerce_finding_fields
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool, _DESCRIPTION_SCHEMA


# ---------- shared helpers ----------

def _scoped_vuln_update(ctx: ActionContext, uuid: str, update: Dict):
	"""Apply a workspace-scoped ``$set`` to the vulnerability with this ``_uuid``.

	Returns ``(modified, updated, label, error_msg)``: ``modified`` docs count,
	the re-fetched vuln (dict, or None), a display ``label`` (the vuln's ``name``,
	falling back to the uuid), and an ``error_msg`` string when nothing matched.

	Uses ``QueryEngine.update`` (an in-place ``$set`` on the matched doc) rather than
	re-yielding the finding, so it works uniformly across backends without risking a
	duplicate insert. On the mongodb driver a ``_uuid`` lookup/update is a native ``_id``
	index seek (the query layer rewrites a valid-ObjectId ``_uuid`` to ``_id`` — findings
	carry ``_uuid = str(_id)``), so the update + re-fetch are point operations, not
	workspace scans. After the update it re-fetches the finding: every backend returns its
	current state (the json store resolves its append-only records last-wins on read).
	"""
	engine = ctx.get_query_engine()
	query = {"_type": "vulnerability", "_uuid": uuid}
	modified = engine.update(query, {"$set": update})
	if not modified:
		return 0, None, uuid, (
			f"No vulnerability found with _uuid={uuid} in this workspace. "
			"Re-check the `_uuid` from query_workspace results."
		)
	# scope_only: a just-marked false-positive is hidden by the `is_false_positive:{$ne:True}`
	# display filter, so a normal re-fetch returns None — `updated` stays empty and `label`
	# falls back to the bare uuid (the chat row then reads "Updated Marked <uuid>…" instead
	# of "Updated <name>", and extra_data.finding is empty). Drop the display filters for this
	# targeted by-uuid read so the finding comes back regardless of its display state.
	updated = (engine.search(query, limit=1, scope_only=True) or [None])[0]
	label = (updated.get("name") if isinstance(updated, dict) else None) or uuid
	return modified, updated, label, None


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
	from secator.query.json import _apply_set
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
			engine.update({"_type": "vulnerability", "_uuid": vu}, {"$set": update})
			_apply_set(v, update)
			if primary is None or not v.get("_duplicate"):
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


# ---------- query_workspace ----------

# Mongo operators the LLM must never send: server-side JS / arbitrary expression
# evaluation (per-document code execution — a DoS and, on some drivers, worse). The
# workspace scope filter still bounds WHICH docs are seen, but a $where runs code
# against each. Workspace queries never legitimately need these.
_FORBIDDEN_QUERY_OPERATORS = frozenset({"$where", "$expr", "$function", "$accumulator"})


# Cap regex length fed to Mongo to bound catastrophic-backtracking DoS (reuses the
# scope engine's ceiling).
_MAX_QUERY_REGEX = 2048


def _validate_query_operators(node) -> Optional[str]:
	"""Recursively reject forbidden Mongo operators and over-long $regex in an LLM
	query. Returns an error message, or None if the query is acceptable."""
	if isinstance(node, dict):
		for key, value in node.items():
			if key in _FORBIDDEN_QUERY_OPERATORS:
				return (f"query operator {key} is not allowed. Use plain field filters "
				        "($in/$regex/$gt/$lt/etc.) on finding fields.")
			if key == "$regex" and isinstance(value, str) and len(value) > _MAX_QUERY_REGEX:
				return f"$regex is too long ({len(value)} chars, max {_MAX_QUERY_REGEX})."
			err = _validate_query_operators(value)
			if err:
				return err
	elif isinstance(node, list):
		for item in node:
			err = _validate_query_operators(item)
			if err:
				return err
	return None


def _resolve_single_output_type(query: Dict):
	"""Resolve the OutputType class for a query that targets exactly one `_type`.

	Returns the class, or None if `_type` is missing, operator-wrapped, multi-valued
	(e.g. `{'$in': [...]}`), or unknown — i.e. the group cannot be unambiguously resolved.
	"""
	from secator.output_types import OUTPUT_TYPES
	type_val = query.get("_type") if isinstance(query, dict) else None
	if not isinstance(type_val, str) or not type_val:
		return None
	return next((cls for cls in OUTPUT_TYPES if cls.get_name() == type_val), None)


class QueryWorkspace(BaseTool):
	name = "query_workspace"
	action = "query"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "query_workspace",
			"description": "Query the workspace database for stored security findings using MongoDB-style queries. "
			               "Example (good): query_workspace(query={'_type':'vulnerability','severity':{'$in':['high','critical']}}, "  # noqa: E501
			               "description='Review high/critical vulns'). "
			               "Bad: query_workspace() — no query; query_workspace(query={}) — unscoped, returns noise.",
			"parameters": {
				"type": "object",
				"properties": {
					"query": {
						"type": "object",
						"description": "MongoDB-style query object (e.g. {\"_type\": \"vulnerability\", \"severity\": {\"$in\": [\"critical\", \"high\"]}})."  # noqa: E501
					},
					"description": _DESCRIPTION_SCHEMA,
					"limit": {
						"type": "integer",
						"description": "Maximum number of results to return.",
						"default": 100
					},
					"offset": {
						"type": "integer",
						"description": "Skip the first N results; use with limit to page through large result sets. "  # noqa: E501
						               "When a full page is returned, the response says the next offset to use.",
						"default": 0
					},
					"group": {
						"type": "boolean",
						"description": "Return aggregated group representatives (one per group, with a _group_count "  # noqa: E501
						               "member count + aggregated targets) instead of every finding — a compact overview "  # noqa: E501
						               "that saves context. Requires a single _type in the query. Each representative is "  # noqa: E501
						               "grouped by that type's key field (shown on the row, e.g. vulnerability->name, "  # noqa: E501
						               "port->host); drill into a group by re-querying that field — NOT the _uuid, which "  # noqa: E501
						               "identifies only the one representative finding.",
						"default": False
					}
				},
				"required": ["query", "description"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Query workspace or current results for findings.

		Args:
			action: Action dict with query (MongoDB query dict)
			ctx: Action context (queries through the run's real driver; live in-run
				findings are unioned in for the local json driver)
		"""
		context = _get_result_context(action, ctx)
		query_filter = action.get("query", {})
		# The schema declares `limit` an integer, but some models send it as a string
		# ("10"); a str limit reaches the backend and raises `'>=' not supported between
		# int and str`. Coerce to int (bad/None values fall back to the default).
		from secator.ai.prompts import AI_MAX_RESULTS
		limit = action.get("limit", AI_MAX_RESULTS)
		try:
			limit = int(limit)
		except (TypeError, ValueError):
			limit = AI_MAX_RESULTS
		offset = action.get("offset", 0)
		try:
			offset = int(offset)
		except (TypeError, ValueError):
			offset = 0
		if offset < 0:
			offset = 0
		group = bool(action.get("group", False))

		# Some providers serialize `query` as a JSON string despite the object schema
		# (known tool-calling quirk); coerce it back, tolerating a stray trailing brace /
		# prose the LLM sometimes appends (loads_lenient), else fail with a clear error.
		if isinstance(query_filter, str):
			try:
				query_filter = loads_lenient(query_filter)
			except (json.JSONDecodeError, TypeError):
				yield Error(
					message='query must be a JSON object (e.g. {"_type": "vulnerability"}); '
					f'got an unparseable string: {query_filter[:120]!r}',
					_context=context,
				)
				return
		if not isinstance(query_filter, dict):
			yield Error(
				message=f'query must be a JSON object; got {type(query_filter).__name__}.',
				_context=context,
			)
			return

		# Decrypt query values
		if ctx.encryptor:
			query_filter = _decrypt_dict(query_filter, ctx.encryptor)

		# Reject server-side-JS / expression operators and over-long regex before the
		# query reaches the DB (workspace scope bounds WHICH docs, not per-doc code cost).
		op_err = _validate_query_operators(query_filter)
		if op_err:
			yield Error(message=op_err, _context=context)
			return

		engine = ctx.get_query_engine()
		is_local = getattr(engine.backend, "name", "") == "json"

		# A non-local backend (mongodb/api) needs a workspace to query. The local (json)
		# driver can always answer from this run's in-memory findings (unioned below), so
		# it is exempt from the workspace_id requirement.
		if not is_local and not ctx.context.get("workspace_id"):
			yield Warning(message="No workspace available for query", _context=context)
			return

		# human-readable intent the LLM supplies (shown as the card title: "Queried <desc>").
		# Normalized BEFORE the try so a FAILED query card keeps the title too.
		description = str(action.get("description") or "").strip()

		try:
			query_str = json.dumps(query_filter, separators=(',', ':'))
			# Surface only the PRIMARY of each finding group: skip hidden duplicates
			# (_context.workspace_duplicate=True) so the AI never operates on a demoted
			# copy — e.g. records a PoC on a doc that isn't the one clients show. Only
			# the mongo-backed drivers (mongodb/api) tag duplicates; the json driver
			# doesn't. Respect an explicit _context filter from the model rather than
			# fighting it. Applied to the search only, so the shown query stays the
			# model's own.
			search_query = query_filter
			if not is_local and "_context" not in query_filter and "_context.workspace_duplicate" not in query_filter:
				search_query = {**query_filter, "_context.workspace_duplicate": {"$ne": True}}

			# Grouped mode: collapse the fetched page to one representative per group so a
			# compact overview (with _group_count + aggregated targets + each rep's _uuid)
			# reaches the model instead of every finding. Requires exactly one _type so we
			# can resolve its _group_by / _group_aggregate.
			group_cls = None
			if group:
				group_cls = _resolve_single_output_type(query_filter)
				if group_cls is None:
					yield Error(
						message="group=True requires the query to target exactly one _type "
						"(e.g. query={'_type': 'vulnerability'}); set a single _type and retry.",
						_context=context,
					)
					return

			results = engine.search(search_query, limit=limit, offset=offset)
			# Local driver only writes to disk at end-of-run, so union this run's live
			# in-flight findings to make query_workspace the source of truth (mongodb/api
			# persist live already, so they need no union).
			if is_local:
				results = _union_live_results(results, ctx.results or [], query_filter, limit)

			page_len = len(results)

			if group_cls is not None:
				from secator.query.utils import group_findings
				results = group_findings(results, list(group_cls._group_by), group_cls._group_aggregate)

			extra = {"results": len(results), "limit": limit, "offset": offset}
			if group:
				extra["group"] = True
			if description:
				extra["description"] = description
			yield Ai(
				content=query_str,
				ai_type="query",
				extra_data=extra,
				_context=context
			)

			# Pagination hint: only when a full page came back (there may be more). Count is
			# only paid for here, not on every query. Grouping summarizes the fetched page,
			# so the next-page hint still pages the underlying findings.
			if limit > 0 and page_len == limit:
				total = engine.count(search_query)
				if total > offset + page_len:
					note = (f"Showing results {offset}-{offset + page_len} of {total}. "
					        f"Re-query with offset={offset + limit} for the next page.")
					if group:
						note += " (group=True summarizes each fetched page; re-group each page.)"
					yield Info(message=note, _context=context)

			for result in results:
				if isinstance(result, OutputType):
					result = result.toDict()
				result["_context"].update(context)
				# Query results are existing workspace findings surfaced for the AI's
				# observation only — mark them so the runner doesn't re-yield/re-report
				# them (which would duplicate them back into the workspace).
				result.setdefault("_context", {})["ai_query_result"] = True
				yield result

		except Exception as e:
			failed_extra = {"results": "failed", "limit": limit}
			if description:
				failed_extra["description"] = description
			yield Ai(
				content=str(query_filter),
				ai_type="query",
				extra_data=failed_extra,
				_context=context
			)
			yield Error.from_exception(e, _context=context)


# ---------- add_finding ----------

class AddFinding(BaseTool):
	name = "add_finding"
	action = "add_finding"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "add_finding",
			"description": "Add a security finding to the workspace (e.g. vulnerability, exploit, url). "
			               "Put the finding's data inside `fields` (NOT as top-level args). "
			               "Example (good): add_finding(_type='vulnerability', fields={'name': 'SQLi in login', 'matched_at': 'http://x/login', 'severity': 'high'}). "  # noqa: E501
			               "Bad: add_finding(_type='vulnerability', name='x') — name/matched_at/... must go inside `fields`.",  # noqa: E501
			"parameters": {
				"type": "object",
				"properties": {
					"_type": {
						"type": "string",
						"description": "The finding type (e.g. vulnerability, exploit, url, port)."
					},
					"fields": {
						"type": "object",
						"description": (
							"The finding's fields for this `_type` (fields vary by type, so put ALL of them "
							"here, e.g. {\"name\": \"SQLi in login\", \"matched_at\": \"http://x/login\", "
							"\"severity\": \"high\"}). MUST be a nested object — passing these as top-level args "
							"makes strict function-calling providers drop them. List fields must be JSON arrays; "
							"`extra_data` must be an object."
						),
						"additionalProperties": True
					}
				},
				"required": ["_type", "fields"],
				"additionalProperties": True
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Create a secator finding from LLM-provided data.

		Args:
			action: Action dict with _type and finding fields
			ctx: Action context
		"""
		context = _get_result_context(action, ctx)

		finding_type = action.get("_type", "")
		# ExploitAttempt records are APPEND-ONLY history created ONLY by the gated mark_vuln_* handlers
		# (which set the verdict + run the vuln rollup). Forbid creating one directly so a `success`
		# verdict can't be forged via add_finding, bypassing the PoC-required gate + the status rollup.
		if finding_type == "exploit_attempt":
			yield Error(
				message="Cannot add an exploit_attempt directly — use mark_vuln_exploited (success) or "
				"mark_vuln_exploit_failed (failed/partial): they record the attempt and derive the "
				"vulnerability's status.", _context=context)
			return
		# Fields arrive nested under `fields` (a DECLARED object param — survives strict
		# function-calling providers that drop undeclared top-level args, the add_finding
		# "arguments stripped to just _type" bug). Fall back to flat siblings for providers
		# that honor additionalProperties, and merge any stragglers a model put at top level.
		_meta = ("action", "_type", "fields", "tool_call_id", "tool_call_name")
		nested = action.get("fields")
		if isinstance(nested, dict):
			flat = {k: v for k, v in action.items() if k not in _meta}
			finding_data = {**flat, **nested}  # nested wins on conflict
		else:
			finding_data = {k: v for k, v in action.items() if k not in _meta}
		# SECURITY: strip framework/server-owned + `*_path` fields the agent must not set (identity,
		# provenance, dedup, verdict/derived) — see _drop_readonly_fields. `_context` is then set
		# server-side below, so the finding is always scoped to THIS session's workspace.
		finding_data = _drop_readonly_fields(finding_data)
		finding_data["_context"] = context

		# Decrypt field values
		if ctx.encryptor:
			finding_data = _decrypt_dict(finding_data, ctx.encryptor)

		# Resolve _type string to OutputType class
		type_map = {cls.get_name(): cls for cls in FINDING_TYPES}
		cls = type_map.get(finding_type)
		if not cls:
			yield Warning(message=f"Unknown finding type: {finding_type}", _context=context)
			return

		# Deserialize JSON strings that should be dicts/lists
		# (LLMs often send structured fields as JSON strings)
		for f in fields(cls):
			if f.name not in finding_data:
				continue
			val = finding_data[f.name]
			if not isinstance(val, str):
				continue
			expected = f.type if isinstance(f.type, type) else getattr(f.type, '__origin__', None)
			if expected in (dict, list):
				try:
					finding_data[f.name] = json.loads(val)
				except (json.JSONDecodeError, TypeError):
					pass

		# Strip unknown fields: move them into extra_data so no data is lost
		known_fields = {f.name for f in fields(cls)}
		unknown = {k: v for k, v in finding_data.items() if k not in known_fields and not k.startswith('_')}
		if unknown:
			finding_data = {k: v for k, v in finding_data.items() if k in known_fields or k.startswith('_')}
			extra = finding_data.get('extra_data', {})
			if isinstance(extra, str):
				try:
					extra = json.loads(extra)
				except (json.JSONDecodeError, TypeError):
					extra = {}
			extra.update(unknown)
			finding_data['extra_data'] = extra

		# Coerce AI-provided scalars to declared field types (LLMs send wrong-typed
		# scalars, e.g. a bool field as the string "true") before validating.
		finding_data = _coerce_finding_fields(cls, finding_data)

		# Validate field types AND required fields before instantiation — a create must carry
		# every mandatory field (require_all), so an omitted required field (e.g. a `tag` without
		# `value`) is rejected with the schema instead of raising a raw TypeError at `cls(**...)`.
		errors = cls.validate_fields(finding_data, require_all=True)
		if errors:
			error_msg = f"Invalid {finding_type} fields: {'; '.join(errors)}.\nExpected schema:\n{cls.schema()}"
			yield Error(message=error_msg, _context=context)
			return

		try:
			finding = cls(**finding_data)
			yield Ai(
				content=f'{str(finding)}',
				ai_type="add_finding",
				# Carry the created finding so clients can render the finding
				# (VulnerabilityCard/SubdomainCard/…) — it routes on `_type`.
				extra_data={"finding": finding.toDict()},
				_context=context
			)
			yield finding
		except Exception as e:
			yield Error(message=f"Failed to create {finding_type}: {e}\nExpected schema:\n{cls.schema()}", _context=context)


# ---------- update_finding ----------

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
			if key and "." not in key and not key.startswith("$"):
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

		updated = _lookup_finding(ctx, uuid)  # every backend reads back the finding as stored
		yield Ai(
			content=f"Updated finding {uuid} ({', '.join(sorted(update.keys()))}).",
			ai_type="update_finding",
			extra_data={"finding": updated} if updated else {},
			_context=context,
		)


# ---------- mark_vuln_exploited ----------

class MarkVulnExploited(BaseTool):
	name = "mark_vuln_exploited"
	action = "mark_vuln_exploited"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "mark_vuln_exploited",
			"description": (
				"Mark an EXISTING vulnerability as exploited after you successfully exploited it, recording "
				"its proof-of-concept. Use this INSTEAD of add_finding(exploit). Identify the vulnerability by "
				"the `_uuid` you saw in query_workspace results. The vuln is set to status='EXPLOITED' "
				"(verified). You MUST provide `poc` — the exact commands and outputs proving a true, "
				"successful exploitation (not just a scanner match). Also provide `remediation` and `impact`, "
				"which fill the vulnerability's own fields (do NOT put them inside the `poc`). The exploitation "
				"date is stamped automatically. This RECORDS an append-only exploit attempt (so parallel "
				"agents accumulate history); the vuln's status is derived server-side from all its attempts "
				"(a prior success stays sticky). Optionally describe it via technique/tool/command/payload/evidence."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark exploited (from query_workspace results)."
					},
					"poc": {
						"type": "string",
						"description": (
							"Markdown proof-of-concept demonstrating a true, successful exploitation (not a scanner "
							"match). Start with `### Description` then `### Details` (the exact commands run and their "
							"real outputs), optionally `### Extracted information`. Do NOT include a title, a "
							"vulnerability summary, or remediation — those live on the vuln itself (its name/"
							"description) and in the `remediation`/`impact` args. Required; be concrete and reproducible."
						)
					},
					"remediation": {
						"type": "string",
						"description": (
							"Markdown remediation steps (prioritized fixes). Fills the vuln's `remediation` field; "
							"do NOT put this inside `poc`. Optional but strongly encouraged."
						)
					},
					"impact": {
						"type": "string",
						"description": (
							"The concrete impact of the confirmed exploitation (what an attacker gains / data at "
							"risk). Fills the vuln's `impact` field; do NOT put this inside `poc`. Optional but "
							"strongly encouraged."
						)
					},
					"confidence": {
						"type": "string",
						"enum": ["low", "medium", "high"],
						"description": "Re-prioritize the vulnerability (e.g. 'high' for a confirmed exploitation). Optional."
					},
					"technique": {
						"type": "string",
						"description": "Exploitation technique/class (e.g. 'SQLi auth bypass', 'SSRF to metadata'). Optional."
					},
					"tool": {
						"type": "string",
						"description": "Tool/framework used (e.g. 'sqlmap', 'manual', 'metasploit'). Optional."
					},
					"command": {
						"type": "string",
						"description": "The exact command run for this attempt. Optional."
					},
					"payload": {
						"type": "string",
						"description": "The payload used. Optional."
					},
					"evidence": {
						"type": "string",
						"description": "Short raw output snippet proving the result. Optional."
					},
					"extra_data": {
						"type": "object",
						"description": "Extra structured context merged into the vuln (existing keys preserved). Optional.",
						"additionalProperties": True
					}
				},
				"required": ["_uuid", "poc"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Mark an EXISTING vulnerability as exploited, recording its proof-of-concept.

		Fills the vuln's ``poc`` (markdown: the commands + outputs proving exploitation) and
		sets ``status=EXPLOITED`` / ``verified=True`` / ``is_false_positive=False`` via a scoped
		``$set`` matched by the ``_uuid`` the LLM saw in ``query_workspace`` results. This is the
		exploitation-result sink used INSTEAD of ``add_finding(exploit)``: an exploited vuln ends
		up with its own filled ``poc``, not a separate Exploit finding. A claimed exploitation
		MUST carry proof — an empty ``poc`` is refused. Also fills the vuln's own ``remediation``
		and ``impact`` fields when supplied, and stamps the exploitation date into the ``poc``
		(the model can't be trusted for the real date, so we set it server-side).
		"""
		from datetime import datetime, timezone
		context = _get_result_context(action, ctx)
		uuid = str(action.get("_uuid") or "").strip()
		poc = action.get("poc") or ""
		remediation = action.get("remediation") or ""
		impact = action.get("impact") or ""
		if ctx.encryptor:
			dec = _decrypt_dict({"poc": poc, "remediation": remediation, "impact": impact}, ctx.encryptor)
			poc = dec.get("poc", poc)
			remediation = dec.get("remediation", remediation)
			impact = dec.get("impact", impact)

		if not uuid:
			yield Error(message="mark_vuln_exploited requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
			return
		if not str(poc).strip():
			yield Error(message="mark_vuln_exploited requires a non-empty `poc` (commands + outputs proving exploitation).", _context=context)  # noqa: E501
			return

		# Stamp the exploitation date at the top of the PoC (authoritative server-side date).
		poc = f"_Exploited on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}_\n\n{str(poc).strip()}"

		# Resolve the vuln this attempt links to (by identity, read from the doc the agent saw).
		vuln = _lookup_finding(ctx, uuid)
		if not vuln or vuln.get("_type") != "vulnerability":
			yield Error(
				message=f"No vulnerability found with _uuid={uuid} in this workspace. "
				"Re-check the `_uuid` from query_workspace results.", _context=context)
			return

		# Record the exploitation as an append-only ExploitAttempt (success) — persisted via the
		# pipeline, so parallel agents accumulate HISTORY instead of overwriting each other.
		attempt = _build_exploit_attempt(ctx, context, vuln, "success", action, poc=poc)
		yield attempt

		# remediation / impact / confidence stay VULN-owned enrichment (not attempt-owned).
		vuln_update = {}
		if str(remediation).strip():
			vuln_update["remediation"] = str(remediation).strip()
		if str(impact).strip():
			vuln_update["impact"] = str(impact).strip()
		# Confidence re-prioritizes the vuln (confidence_nb: high=1 sorts first .. low=3).
		confidence = str(action.get("confidence") or "").strip().lower()
		if confidence in ("low", "medium", "high"):
			vuln_update["confidence"] = confidence
			vuln_update["confidence_nb"] = {"high": 1, "medium": 2, "low": 3}[confidence]
		_merge_extra_data(vuln_update, action.get("extra_data"))
		if vuln_update:
			try:
				_scoped_vuln_update(ctx, uuid, vuln_update)
			except Exception as e:
				yield Error(message=f"Failed to enrich vulnerability: {e}", _context=context)
				return

		# Derive the vuln's status/verified/poc from ALL its attempts (success sticky).
		try:
			updated = _recompute_vuln_rollup(
				ctx, vuln.get("name", ""), vuln.get("id", ""), vuln.get("matched_at", ""), pending=attempt)
		except Exception as e:
			yield Error(message=f"Failed to mark vulnerability exploited: {e}", _context=context)
			return
		label = (updated or vuln).get("name") or uuid
		yield Ai(
			content=f"Marked {label} as exploited (PoC recorded).",
			ai_type="mark_vuln_exploited",
			extra_data={"finding": updated, "attempt": attempt.toDict()} if updated else {"attempt": attempt.toDict()},
			_context=context,
		)


# ---------- mark_vuln_exploit_failed ----------

class MarkVulnExploitFailed(BaseTool):
	name = "mark_vuln_exploit_failed"
	action = "mark_vuln_exploit_failed"
	auto_allow = True
	schema = {
		"type": "function",
		"function": {
			"name": "mark_vuln_exploit_failed",
			"description": (
				"Mark an EXISTING vulnerability as EXPLOIT FAILED — a REAL vulnerability that YOU could not "
				"exploit in this attempt. Identify it by the `_uuid` from query_workspace results. Sets "
				"status='EXPLOIT FAILED' but keeps the vuln VISIBLE and retryable (does NOT hide it) — a later "
				"attempt may succeed, and the remediation still applies. Use this (NOT mark_vuln_false_positive) "
				"whenever the vuln is genuine but your exploitation didn't land. Give a short `reason`; provide "
				"`remediation`/`impact` if you assessed them. This RECORDS an append-only exploit attempt "
				"(failed, or 'partial' if you made progress); the vuln's status is derived from all attempts, "
				"so a prior success is never overwritten. Optionally describe it via technique/tool/command/"
				"payload/evidence."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark exploit-failed (from query_workspace results)."
					},
					"verdict": {
						"type": "string",
						"enum": ["failed", "partial"],
						"description": "'failed' (default) or 'partial' if you made meaningful progress but no full compromise."
					},
					"reason": {
						"type": "string",
						"description": "Short reason the exploit didn't land (e.g. 'WAF blocked payload', 'no reachable sink'). Recorded on the vuln."  # noqa: E501
					},
					"remediation": {
						"type": "string",
						"description": "Markdown remediation steps for the vuln (it still applies). Fills the vuln's `remediation` field. Optional."  # noqa: E501
					},
					"impact": {
						"type": "string",
						"description": "The potential impact if it were exploited. Fills the vuln's `impact` field. Optional."
					},
					"technique": {
						"type": "string",
						"description": "Exploitation technique/class attempted (e.g. 'SQLi auth bypass'). Optional."
					},
					"tool": {
						"type": "string",
						"description": "Tool/framework used (e.g. 'sqlmap', 'manual'). Optional."
					},
					"command": {
						"type": "string",
						"description": "The exact command run for this attempt. Optional."
					},
					"payload": {
						"type": "string",
						"description": "The payload used. Optional."
					},
					"evidence": {
						"type": "string",
						"description": "Short raw output snippet showing the result. Optional."
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
		"""Mark an EXISTING vulnerability as EXPLOIT FAILED — a real vuln this attempt could not
		exploit, kept VISIBLE so a later attempt can retry (unlike mark_vuln_false_positive, which
		hides a not-real finding). Sets ``status="EXPLOIT FAILED"`` via a scoped ``$set`` matched by
		``_uuid``; leaves ``is_false_positive`` and ``verified`` untouched. Fills ``remediation`` /
		``impact`` when supplied (they still apply), and stores an optional ``reason`` in
		``extra_data.exploit_failed_reason``.
		"""
		context = _get_result_context(action, ctx)
		uuid = str(action.get("_uuid") or "").strip()
		if not uuid:
			yield Error(message="mark_vuln_exploit_failed requires the vulnerability `_uuid` (from query_workspace results).", _context=context)  # noqa: E501
			return
		reason = str(action.get("reason") or "").strip()
		remediation = action.get("remediation") or ""
		impact = action.get("impact") or ""
		if ctx.encryptor:
			dec = _decrypt_dict({"reason": reason, "remediation": remediation, "impact": impact}, ctx.encryptor)
			reason = dec.get("reason", reason)
			remediation = dec.get("remediation", remediation)
			impact = dec.get("impact", impact)

		# verdict: 'failed' (default) or 'partial' (made progress, not a full compromise).
		verdict = str(action.get("verdict") or "failed").strip().lower()
		if verdict not in ("failed", "partial"):
			verdict = "failed"

		vuln = _lookup_finding(ctx, uuid)
		if not vuln or vuln.get("_type") != "vulnerability":
			yield Error(
				message=f"No vulnerability found with _uuid={uuid} in this workspace. "
				"Re-check the `_uuid` from query_workspace results.", _context=context)
			return

		# Record the failed/partial attempt as append-only history (kept VISIBLE — a later attempt
		# can still succeed; the rollup keeps a prior success sticky).
		attempt = _build_exploit_attempt(ctx, context, vuln, verdict, action, reason=reason)
		yield attempt

		# remediation / impact stay vuln-owned enrichment (they still apply even on a failed attempt).
		vuln_update = {}
		if str(remediation).strip():
			vuln_update["remediation"] = str(remediation).strip()
		if str(impact).strip():
			vuln_update["impact"] = str(impact).strip()
		if reason:
			vuln_update["extra_data.exploit_failed_reason"] = reason
		_merge_extra_data(vuln_update, action.get("extra_data"))
		if vuln_update:
			try:
				_scoped_vuln_update(ctx, uuid, vuln_update)
			except Exception as e:
				yield Error(message=f"Failed to enrich vulnerability: {e}", _context=context)
				return

		try:
			updated = _recompute_vuln_rollup(
				ctx, vuln.get("name", ""), vuln.get("id", ""), vuln.get("matched_at", ""), pending=attempt)
		except Exception as e:
			yield Error(message=f"Failed to mark vulnerability exploit-failed: {e}", _context=context)
			return
		label = (updated or vuln).get("name") or uuid
		msg = f"Recorded {verdict} exploit attempt on {label}" + (f" ({reason})." if reason else ".")
		yield Ai(
			content=msg,
			ai_type="mark_vuln_exploit_failed",
			extra_data={"finding": updated, "attempt": attempt.toDict()} if updated else {"attempt": attempt.toDict()},
			_context=context,
		)


# ---------- mark_vuln_false_positive ----------

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
			modified, updated, label, err = _scoped_vuln_update(ctx, uuid, update)
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


# ---------- mark_vuln_fixed ----------

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
		update = {"status": "FIXED", "verified": False}
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


# ---------- add_note ----------

# target_type -> ordered identity ("dedup key") field names, per core OutputType. This is the
# SAME per-type identity the notes store keys off (the ``compare=True`` non-underscore dataclass
# fields = ``OutputType._compare_key``): a url keys off {url}, a port off {port, ip, state}, a
# vulnerability off {name, id, matched_at}. Those survive a re-scan's _uuid churn, so a note
# re-attaches to the re-found finding. Every notes store derives the identity the same way.
_NOTE_IDENTITY_FIELDS = {
	cls.get_name(): [f.name for f in fields(cls) if f.compare and not f.name.startswith("_")]
	for cls in FINDING_TYPES
}


def _note_stringify(v) -> str:
	"""Coerce an identity value to the stable string form stored in a note's target_key.

	Finding identity fields can be ints/bools (e.g. ``port``, ``state``); the stored key is a
	string map so a note written here compares byte-for-byte with one posted via the api
	driver's notes endpoint (which stringifies the same way)."""
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
		locally; the ``api`` driver POSTs it to the api driver's notes endpoint (author + timestamps
		set by the notes store). The finding itself is never modified.
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
