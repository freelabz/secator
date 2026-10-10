"""Single source of truth for native LLM tools.

Each tool is one self-contained ``BaseTool`` subclass carrying everything that
used to be hand-synced across 5 places (schema, dispatch action, mode exposure,
permission auto-allow, handler). The ``TOOLS`` registry is built from the
subclasses, and every drift-prone view derives from it:

* ``build_tool_schemas(mode, ...)`` filters ``TOOLS`` by ``mode in tool.modes``.
* ``TOOL_ACTION_MAP`` / ``TOOL_SCHEMAS`` are derived dicts (kept for callers).
* ``dispatch_action`` (actions.py) routes via ``TOOLS_BY_ACTION[action].handle``.
* ``PermissionEngine`` (guardrails.py) reads ``tool.auto_allow``.

Adding a tool is ONE edit: define a ``BaseTool`` subclass and list it in
``_TOOL_CLASSES``. The consistency test (test_ai_tools) fails if a tool's mode
exposure and a mode's ``allowed_actions`` drift apart.
"""

import json

from secator.ai.prompts import MODES, normalize_mode

# Shared "targets" parameter schema (identical across run_task/run_workflow)
_TARGETS_SCHEMA = {
	"type": "array",
	"items": {"type": "string"},
	"description": "List of targets (hosts, URLs, IPs)."
}

_DESCRIPTION_SCHEMA = {
	"type": "string",
	"description": "A short plain-English statement of your INTENT — WHY you are running this, in 4-10 words. "
	               "Do NOT paste the command, and do NOT just repeat the task name; describe the PURPOSE. "
	               "BAD (never do this): 'nmap', 'httpx', 'curl -sk http://...'. "
	               "GOOD: 'Scan for open services and versions', 'Probe which HTTP methods are allowed', "
	               "'Fire the reflected-XSS payload at level 1'. Shown to the user in place of the bare task name."
}

# Mode-membership sets, so each tool declares exposure declaratively. These mirror
# the per-mode ``allowed_actions`` in prompts.MODES (enforced by the consistency test).
_SCAN_EXPLOIT = frozenset({"scan", "exploit"})
_ALL_MODES = frozenset({"scan", "chat", "exploit"})


class BaseTool:
	"""One AI tool. Subclasses set the class attributes; the registry does the rest.

	Attributes:
		name: Tool function name exposed to the LLM (e.g. ``run_task``).
		action: Dispatch key / action type used by handlers (e.g. ``task``).
		schema: OpenAI-format function schema dict.
		modes: Set of modes that expose this tool (``build_tool_schemas`` filter).
		auto_allow: True if ``PermissionEngine`` auto-allows this action at the
			action-type layer (no name/scope rule needed). task/workflow/shell are
			False — they have their own layer-1 handling.
		injected: True for a tool NOT emitted by ``build_tool_schemas`` mode
			filtering and NOT listed in ``TOOL_SCHEMAS``; it is injected separately
			via the interactivity backend's ``get_extra_tools`` (``stop``).
		handler: Name of the ``_handle_*`` generator in ``secator.ai.actions``.
	"""

	name: str = ""
	action: str = ""
	schema: dict = {}
	modes: frozenset = frozenset()
	auto_allow: bool = False
	injected: bool = False
	handler: str = ""

	def handle(self, action, ctx):
		"""Dispatch to the existing ``_handle_*`` generator (logic unchanged).

		Lazy import avoids a tools<->actions import cycle (actions dispatches back
		through this registry).
		"""
		from secator.ai import actions
		return getattr(actions, self.handler)(action, ctx)


class RunTaskTool(BaseTool):
	name = "run_task"
	action = "task"
	modes = _SCAN_EXPLOIT
	handler = "_handle_task"
	schema = {
		"type": "function",
		"function": {
			"name": "run_task",
			"description": "Run a secator security task (e.g. nmap, httpx, nuclei) against targets. To spawn an AI subagent use run_subagent (NOT name='ai'). "  # noqa: E501
			               "Example (good): run_task(name='nmap', targets=['10.0.0.1'], opts={'ports':'1-1000'}, description='Scan common ports'). "  # noqa: E501
			               "Bad: run_task(name='nmap') — no targets; run_task() — no args.",
			"parameters": {
				"type": "object",
				"properties": {
					"name": {
						"type": "string",
						"description": "The task name (e.g. nmap, httpx, nuclei, ffuf)."
					},
					"targets": _TARGETS_SCHEMA,
					"description": _DESCRIPTION_SCHEMA,
					"opts": {
						"type": "object",
						"description": "Optional task-specific options (e.g. ports, rate_limit). Control/security flags are ignored."
					}
				},
				"required": ["name", "targets", "description"]
			}
		}
	}


class RunSubagentTool(BaseTool):
	name = "run_subagent"
	action = "subagent"
	modes = _ALL_MODES
	auto_allow = True
	handler = "_handle_subagent"
	schema = {
		"type": "function",
		"function": {
			"name": "run_subagent",
			"description": (
				"Spawn an autonomous AI subagent with a fresh context window that works the objective "
				"non-interactively and hands back a summary — the ONLY way to spawn a subagent (do NOT "
				"use run_task with name='ai'). Use it to parallelize or offload a focused sub-task.\n"
				"Mode: in an AUTO or scan session you MAY set `mode` to pick the subagent's mode "
				"(e.g. hand a confirmed vuln to an `exploit` subagent). In a user-PINNED read-only `chat` "
				"session the subagent is forced to `chat`; do NOT set a different `mode` there.\n"
				"Example (good): run_subagent(objective='Validate and exploit CVE-2021-41773 on "
				"10.0.0.9, record a PoC', targets=['10.0.0.9'], "
				"description='Exploit the Apache path traversal', mode='exploit'). "
				"Bad: run_subagent(objective='do stuff') — no targets, vague objective."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"objective": {
						"type": "string",
						"description": "The subagent's goal, with ALL context it needs (target details, "
						               "relevant findings as raw JSON, credentials/versions). It has a fresh "
						               "context window and sees only what you pass here."
					},
					"targets": _TARGETS_SCHEMA,
					"description": _DESCRIPTION_SCHEMA,
					"mode": {
						"type": "string",
						"enum": ["chat", "scan", "exploit"],
						"description": "Optional mode for the subagent (chat/scan/exploit). Honored only in an "
						               "auto or scan session; ignored/forced to chat in a pinned chat session. "
						               "Omit to inherit the current mode."
					},
					"model": {
						"type": "string",
						"description": "Optional LLM model id for the subagent. Omit to inherit the current model."
					}
				},
				"required": ["objective", "targets", "description"]
			}
		}
	}


class RunWorkflowTool(BaseTool):
	name = "run_workflow"
	action = "workflow"
	modes = _SCAN_EXPLOIT
	handler = "_handle_workflow"
	schema = {
		"type": "function",
		"function": {
			"name": "run_workflow",
			"description": "Run a secator workflow (a composed sequence of tasks) against one or more targets.",
			"parameters": {
				"type": "object",
				"properties": {
					"name": {
						"type": "string",
						"description": "The workflow name."
					},
					"targets": _TARGETS_SCHEMA,
					"description": _DESCRIPTION_SCHEMA,
					"opts": {
						"type": "object",
						"description": "Optional workflow options (e.g. profiles). Control/security flags are ignored."
					}
				},
				"required": ["name", "targets", "description"]
			}
		}
	}


class RunShellTool(BaseTool):
	name = "run_shell"
	action = "shell"
	modes = _SCAN_EXPLOIT
	handler = "_handle_shell"
	schema = {
		"type": "function",
		"function": {
			"name": "run_shell",
			"description": "Run an arbitrary shell command for exploration, exploitation, or data analysis. "
			               "Example (good): run_shell(command='curl -sk https://10.0.0.1/ | head -50', description='Grab the HTTP banner'). "  # noqa: E501
			               "Bad: run_shell() — no command.",
			"parameters": {
				"type": "object",
				"properties": {
					"command": {
						"type": "string",
						"description": "The shell command to execute."
					},
					"description": _DESCRIPTION_SCHEMA
				},
				"required": ["command", "description"]
			}
		}
	}


class QueryWorkspaceTool(BaseTool):
	name = "query_workspace"
	action = "query"
	modes = _ALL_MODES
	auto_allow = True
	handler = "_handle_query"
	schema = {
		"type": "function",
		"function": {
			"name": "query_workspace",
			"description": "Query the workspace database for stored security findings using MongoDB-style queries. "
			               "Example (good): query_workspace(query={'_type':'vulnerability','severity':{'$in':['high','critical']}}). "  # noqa: E501
			               "Bad: query_workspace() — no query; query_workspace(query={}) — unscoped, returns noise.",
			"parameters": {
				"type": "object",
				"properties": {
					"query": {
						"type": "object",
						"description": "MongoDB-style query object (e.g. {\"_type\": \"vulnerability\", \"severity\": {\"$in\": [\"critical\", \"high\"]}})."  # noqa: E501
					},
					"limit": {
						"type": "integer",
						"description": "Maximum number of results to return.",
						"default": 100
					}
				},
				"required": ["query"]
			}
		}
	}


class FollowUpTool(BaseTool):
	name = "follow_up"
	action = "follow_up"
	modes = _ALL_MODES
	auto_allow = True
	handler = "_handle_follow_up"
	schema = {
		"type": "function",
		"function": {
			"name": "follow_up",
			"description": "Ask the user a follow-up question to clarify next steps or present options.",
			"parameters": {
				"type": "object",
				"properties": {
					"reason": {
						"type": "string",
						"description": "Why follow-up is needed."
					},
					"choices": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Optional list of concrete action choices for the user."
					},
					"multiple": {
						"type": "boolean",
						"description": "Set true when the user may select SEVERAL of the choices (multi-select); omit or false for a pick-exactly-one question."  # noqa: E501
					}
				},
				"required": ["reason"]
			}
		}
	}


class AddFindingTool(BaseTool):
	name = "add_finding"
	action = "add_finding"
	modes = _SCAN_EXPLOIT
	auto_allow = True
	handler = "_handle_add_finding"
	schema = {
		"type": "function",
		"function": {
			"name": "add_finding",
			"description": "Add a security finding to the workspace (e.g. vulnerability, exploit, url). "
			               "Example (good): add_finding(_type='vulnerability', name='SQLi in login', matched_at='http://x/login', severity='high'). "  # noqa: E501
			               "Bad: add_finding(name='x', extra_data='y') — missing _type/matched_at, extra_data must be a dict.",
			"parameters": {
				"type": "object",
				"properties": {
					"_type": {
						"type": "string",
						"description": "The finding type (e.g. vulnerability, exploit, url, port)."
					}
				},
				"required": ["_type"],
				"additionalProperties": True
			}
		}
	}


class MarkVulnExploitedTool(BaseTool):
	name = "mark_vuln_exploited"
	action = "mark_vuln_exploited"
	modes = _SCAN_EXPLOIT
	auto_allow = True
	handler = "_handle_mark_vuln_exploited"
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
				"date is stamped automatically."
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


class MarkVulnFalsePositiveTool(BaseTool):
	name = "mark_vuln_false_positive"
	action = "mark_vuln_false_positive"
	modes = _SCAN_EXPLOIT
	auto_allow = True
	handler = "_handle_mark_vuln_false_positive"
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


class MarkVulnExploitFailedTool(BaseTool):
	name = "mark_vuln_exploit_failed"
	action = "mark_vuln_exploit_failed"
	modes = _SCAN_EXPLOIT
	auto_allow = True
	handler = "_handle_mark_vuln_exploit_failed"
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
				"`remediation`/`impact` if you assessed them."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"_uuid": {
						"type": "string",
						"description": "The `_uuid` of the vulnerability to mark exploit-failed (from query_workspace results)."
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


class UpdateFindingTool(BaseTool):
	name = "update_finding"
	action = "update_finding"
	modes = _SCAN_EXPLOIT
	auto_allow = True
	handler = "_handle_update_finding"
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


class ChangeModeTool(BaseTool):
	name = "change_mode"
	action = "change_mode"
	modes = _ALL_MODES
	auto_allow = True
	handler = "_handle_change_mode"
	schema = {
		"type": "function",
		"function": {
			"name": "change_mode",
			"description": (  # noqa: E501
				"Switch your OWN operating mode when the task needs capabilities your current mode lacks. "
				"If you are in read-only chat and the user asks you to scan, do recon, attack, or exploit, "
				"call change_mode(mode='scan') and then carry out the request — do NOT ask the user to "
				"switch modes, change it yourself. 'scan' unlocks tasks/workflows/shell + finding writes; "
				"'exploit' is for focused exploitation of a known vulnerability. "
				"Example (good): change_mode(mode='scan', reason='user asked to run reconnaissance')."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"mode": {
						"type": "string",
						"enum": ["scan", "exploit"],
						"description": "The mode to switch to: 'scan' (recon/scanning/active testing) or 'exploit'."
					},
					"reason": {
						"type": "string",
						"description": "Short reason for the switch (optional)."
					}
				},
				"required": ["mode"]
			}
		}
	}


class StopTool(BaseTool):
	name = "stop"
	action = "stop"
	modes = _ALL_MODES
	auto_allow = True
	# NOT emitted by build_tool_schemas / not in TOOL_SCHEMAS — injected by
	# AutoBackend via get_extra_tools (no user to hand control back to).
	injected = True
	handler = "_handle_stop"
	schema = {
		"type": "function",
		"function": {
			"name": "stop",
			"description": "Stop the current session. Call when the user request has been fulfilled or when you encounter a blocker that cannot be resolved without user input.",  # noqa: E501
			"parameters": {
				"type": "object",
				"properties": {
					"reason": {
						"type": "string",
						"description": "Why you are stopping (summary of accomplishments or description of blocker)."
					}
				},
				"required": ["reason"]
			}
		}
	}


# The registry: order mirrors the historical TOOL_SCHEMAS order so build_tool_schemas
# emits tools in the same order as before (parity).
_TOOL_CLASSES = [
	RunTaskTool,
	RunSubagentTool,
	RunWorkflowTool,
	RunShellTool,
	QueryWorkspaceTool,
	FollowUpTool,
	AddFindingTool,
	MarkVulnExploitedTool,
	MarkVulnFalsePositiveTool,
	MarkVulnExploitFailedTool,
	UpdateFindingTool,
	ChangeModeTool,
	StopTool,
]

TOOLS = [cls() for cls in _TOOL_CLASSES]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}
TOOLS_BY_ACTION = {t.action: t for t in TOOLS}

# Derived views (kept for existing callers; no longer hand-synced). TOOL_SCHEMAS
# excludes `injected` tools (stop), matching the historical contract.
TOOL_ACTION_MAP = {t.name: t.action for t in TOOLS}
TOOL_SCHEMAS = {t.name: t.schema for t in TOOLS if not t.injected}

# Stop tool schema — NOT in TOOL_SCHEMAS (injected by AutoBackend via get_extra_tools).
STOP_TOOL_SCHEMA = TOOLS_BY_NAME["stop"].schema


def build_tool_schemas(mode: str, is_subagent: bool = False, backend=None, mode_is_auto: bool = True) -> list:
	"""Return list of tool schemas exposed in a mode (derived from the registry).

	Args:
		mode: The AI mode (scan, chat, exploit). Unknown modes fall back to chat.
		is_subagent: If True, exclude follow_up + change_mode (a subagent runs at its
			assigned mode and does not self-escalate / hand back to a user).
		backend: Optional interactivity backend for exclusion/extra tools.
		mode_is_auto: Whether the session is in auto mode (vs a user-pinned mode).
			Gates `change_mode`: the model may self-escalate in an auto session or from
			a pinned ACTION mode, but a user-PINNED read-only `chat` must stay read-only,
			so `change_mode` is withheld there (the model can only suggest the user
			switches). An auto session that happens to resolve to chat KEEPS change_mode.

	Returns:
		List of OpenAI-format tool schema dicts.
	"""
	# An unknown mode exposes the same tools as chat (historical fallback), but the
	# pinned-chat `change_mode` gate below keys off the ORIGINAL mode name — an unknown
	# mode is not literally `chat`, so it is NOT withheld there (parity with the prior
	# get_mode_config-based filter, which only used the chat fallback for tool exposure).
	norm = normalize_mode(mode)
	lookup_mode = norm if norm in MODES else "chat"
	excluded = set()
	if is_subagent:
		# A subagent runs at its assigned mode; it does not self-escalate or hand back.
		excluded.update({"follow_up", "change_mode"})
	# A user-pinned read-only chat cannot self-escape to an action mode.
	if not mode_is_auto and mode == "chat":
		excluded.add("change_mode")
	if backend is not None:
		excluded.update(backend.get_excluded_tools())
	schemas = [
		t.schema for t in TOOLS
		if not t.injected and lookup_mode in t.modes and t.name not in excluded
	]
	if backend is not None:
		schemas.extend(backend.get_extra_tools())
	return schemas


def coerce_stringified_args(tool_name: str, arguments: dict) -> dict:
	"""Coerce args the model serialized as JSON strings back to their declared type.

	Some providers stringify nested object/array parameters even when the tool
	schema says ``type: object`` / ``array`` (e.g. ``opts`` or ``query`` arriving
	as a JSON string). Downstream handlers then call ``.get()`` / ``**opts`` /
	``.items()`` on a ``str`` and raise ``AttributeError`` — or silently drop the
	value (``_sanitize_child_opts`` returns ``{}`` for a non-dict). Parse any such
	arg once, here at the tool-call boundary, so every consumer gets the declared
	type. Best-effort: an unparseable value is left as-is so the handler can return
	a clean error rather than crash.

	Must run BEFORE arg decryption — ``_decrypt_dict`` would otherwise treat a
	stringified object as a single encrypted value.
	"""
	if not isinstance(arguments, dict):
		return arguments
	props = TOOL_SCHEMAS.get(tool_name, {}).get("function", {}).get("parameters", {}).get("properties", {})
	for key, spec in props.items():
		if spec.get("type") in ("object", "array") and isinstance(arguments.get(key), str):
			try:
				arguments[key] = json.loads(arguments[key])
			except (json.JSONDecodeError, TypeError, ValueError):
				pass
	return arguments


def tool_call_to_action(tool_name: str, arguments: dict) -> dict | None:
	"""Convert a tool call to an action dict compatible with existing action handlers.

	Args:
		tool_name: The tool function name from the LLM response.
		arguments: The parsed arguments dict from the LLM response.

	Returns:
		Action dict with "action" key added, or None for unknown tools.
	"""
	action_type = TOOL_ACTION_MAP.get(tool_name)
	if action_type is None:
		return None
	if not arguments:
		# `stop` ends the turn and carries no required data (its `reason` is optional),
		# so a bare stop() with empty/no args is VALID and must succeed — otherwise the
		# empty-args reject below bounces every clean stop as "empty arguments" and the
		# model falls back into a follow-up nag loop instead of ending. Every other tool
		# needs arguments, so keep rejecting those. Covers native + text-parsed stop.
		if tool_name == "stop":
			return {"action": action_type, "description": "stopped"}
		return None
	# A model may emit non-object arguments (bare JSON int/array/string) -- `.items()`
	# below would raise and abort the loop, so reject cleanly and let the caller retry.
	if not isinstance(arguments, dict):
		return None
	safe_arguments = {k: v for k, v in arguments.items() if k not in {"action", "description"}}
	# Some models routinely drop the leading underscore on the `_uuid` identity arg,
	# sending `uuid` instead — every finding tool (mark_vuln_exploited /
	# mark_vuln_false_positive / update_finding) then errors "requires `_uuid`".
	# Normalize the common misspelling so the intent isn't lost to a naming quirk.
	if "uuid" in safe_arguments and "_uuid" not in safe_arguments:
		safe_arguments["_uuid"] = safe_arguments.pop("uuid")
	# Prefer the description the model was asked to provide (run_task/run_workflow/run_shell all
	# require it); fall back to name/query/command only when it's missing. Was previously dropped
	# here, so the AI-chat background-tasks list showed the raw command instead of the description.
	descr = (
		arguments.get("description")
		or safe_arguments.get("name", "")
		or safe_arguments.get("query")
		or safe_arguments.get("command")
		or safe_arguments.get("mode")
		or "unknown"
	)
	return {"action": action_type, "description": descr, **safe_arguments}
