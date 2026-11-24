"""AI tool: `query_workspace`."""
import json
from typing import Dict, Generator, Optional
from secator.output_types import FINDING_TYPES, Ai, Error, Info, OutputType, Warning
from secator.ai.utils import _decrypt_dict, _union_live_results, loads_lenient
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool, _DESCRIPTION_SCHEMA


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


def _single_row(result):
	"""One group row for a finding whose type has no group key: the finding is its own group."""
	get = result.get if isinstance(result, dict) else lambda k, d=None: getattr(result, k, d)
	uuid = get('_uuid') or ''
	extra = {
		'_group_key': uuid,
		'_group_count': 1,
		'_group_uuids': [uuid] if uuid else [],
		'_group_members': {str(get('_source') or ''): [uuid]} if uuid else {},
	}
	for name, val in extra.items():
		if isinstance(result, dict):
			result[name] = val
		else:
			setattr(result, name, val)
	return result


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
						"description": "Return one row per entity instead of every finding: the duplicates of a "  # noqa: E501
						               "finding across runs and tools collapse into one row. Requires a single _type. Keys: "  # noqa: E501
						               "port->host:port (ip:port), url->url, ip->ip, subdomain->host, domain->domain, "  # noqa: E501
						               "certificate->host+fingerprint, record->host+type+name, user_account->site_name+username, "  # noqa: E501
						               "technology->product:version, vulnerability->id (name), tag->category+name+value, exploit->name; "  # noqa: E501
						               "exploit_attempt is one row per attempt. Each row has _group_key, "  # noqa: E501
						               "_group_count, _group_uuids (EVERY member's _uuid) and _group_members ({value: [_uuids]}, "  # noqa: E501
						               "values: matched_at for vulnerability/exploit, match for technology/tag, host for ip, else _source).",  # noqa: E501
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
				if not group_cls._group_by and (group_cls is Ai or group_cls not in FINDING_TYPES):
					yield Error(message=f"group=True is not supported for {group_cls.get_name()} (no group key).", _context=context)
					return

			results = engine.search(search_query, limit=limit, offset=offset)
			# Local driver only writes to disk at end-of-run, so union this run's live
			# in-flight findings to make query_workspace the source of truth (mongodb/api
			# persist live already, so they need no union).
			if is_local:
				results = _union_live_results(results, ctx.results or [], query_filter, limit)

			page_len = len(results)

			if group_cls is not None and group_cls._group_by:
				from secator.query.utils import group_findings
				results = group_findings(
					results, list(group_cls._group_by), group_cls._group_aggregate, with_members=True)
			elif group_cls is not None:
				# A finding type without a group key (e.g. exploit_attempt: each attempt is
				# distinct) is one row per document, with the same group fields.
				results = [_single_row(r) for r in results]

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
