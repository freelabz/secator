"""AI tool: `add_finding`."""
import json
from dataclasses import fields
from typing import Dict, Generator
from secator.output_types import Ai, Error, FINDING_TYPES, Warning
from secator.ai.utils import _coerce_finding_fields, _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools._findings import _drop_readonly_fields
from secator.ai.tools.base import BaseTool


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
