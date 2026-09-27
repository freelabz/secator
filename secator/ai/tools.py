"""Tool schema definitions for native LLM tool calling."""

import json

from secator.ai.prompts import get_mode_config

# Map tool names to action types used by existing action handlers
TOOL_ACTION_MAP = {
	"run_task": "task",
	"run_subagent": "subagent",
	"run_workflow": "workflow",
	"run_shell": "shell",
	"query_workspace": "query",
	"fetch_url": "fetch_url",
	"add_finding": "add_finding",
	"mark_vuln_exploited": "mark_vuln_exploited",
	"mark_vuln_false_positive": "mark_vuln_false_positive",
	"mark_vuln_exploit_failed": "mark_vuln_exploit_failed",
	"update_finding": "update_finding",
	"change_mode": "change_mode",
	"stop": "stop",
}

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

# OpenAI-format tool schemas keyed by tool name
TOOL_SCHEMAS = {
	"run_task": {
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
	},
	"run_subagent": {
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
	},
	"run_workflow": {
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
	},
	"run_shell": {
		"type": "function",
		"function": {
			"name": "run_shell",
			"description": "Run an arbitrary shell command for exploration, exploitation, or data analysis. "
			               "Commands default to a 30s timeout; if one times out and just needs longer (a slow "
			               "install, a long scan), re-run it with a higher `timeout`. "
			               "Example (good): run_shell(command='curl -sk https://10.0.0.1/ | head -50', description='Grab the HTTP banner'). "  # noqa: E501
			               "Bad: run_shell() — no command.",
			"parameters": {
				"type": "object",
				"properties": {
					"command": {
						"type": "string",
						"description": "The shell command to execute."
					},
					"timeout": {
						"type": "integer",
						"description": "Optional max run time in seconds for THIS command (default 30). Raise it for a "
						               "slow command (install, long scan) and re-run after a timeout. Capped at the "
						               "server's configured maximum task timeout; values below the default are floored."  # noqa: E501
					},
					"description": _DESCRIPTION_SCHEMA
				},
				"required": ["command", "description"]
			}
		}
	},
	"query_workspace": {
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
	},
	"add_finding": {
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
	},
	"mark_vuln_exploited": {
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
	},
	"mark_vuln_false_positive": {
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
	},
	"mark_vuln_exploit_failed": {
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
	},
	"update_finding": {
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
	},
	"change_mode": {
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
	},
	"fetch_url": {
		"type": "function",
		"function": {
			"name": "fetch_url",
			"description": (
				"Fetch a single PUBLIC web page and return its readable text — use it to READ a page you "
				"already know (a HackTricks technique, a vendor advisory, a Debian security-tracker page, a "
				"blog post on a fresh CVE). Only public "
				"http(s) pages are allowed; internal/private hosts are refused."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "The http(s) URL to fetch."},
					"max_chars": {"type": "integer", "description": "Max characters of extracted text to return (default 20000)."}
				},
				"required": ["url"]
			}
		}
	},
}


# Stop tool schemas — NOT in TOOL_SCHEMAS; injected per-backend via get_extra_tools().
# `stop` is the SINGLE end-of-turn signal in every mode: the backend's own ask_user
# decides what happens next (interactive pause / wait, or non-interactive end).

# Interactive stop (TUI / CLI / remote): may carry `choices`/`multiple` so the pause
# offers the user concrete next steps to pick from.
STOP_TOOL_SCHEMA = {
	"type": "function",
	"function": {
		"name": "stop",
		"description": "End your turn. Call when the user's request has been fulfilled, or when you hit a blocker "  # noqa: E501
		               "you cannot resolve without user input. Offer concrete next steps via `choices` (renders as "  # noqa: E501
		               "clickable buttons); omit `choices` when the task is simply complete.",
		"parameters": {
			"type": "object",
			"properties": {
				"reason": {
					"type": "string",
					"description": "Why you are stopping (summary of accomplishments or description of blocker)."
				},
				"choices": {
					"type": "array",
					"items": {"type": "string"},
					"description": "Optional list of concrete action choices to offer the user as next steps."
				},
				"multiple": {
					"type": "boolean",
					"description": "Set true when the choices are NOT mutually exclusive and the user could pick SEVERAL "  # noqa: E501
					               "(multi-select) — common for independent next actions, e.g. ['Port scan', 'Directory "  # noqa: E501
					               "brute-force', 'Vulnerability scan'] the user may want to run together. Omit or false "  # noqa: E501
					               "only for a genuine pick-exactly-one question (e.g. 'Which target?')."
				}
			},
			"required": ["reason"]
		}
	}
}

# Non-interactive stop (AutoBackend: subagents + autonomous workers): a DEFINITIVE stop,
# so NO `choices` — there is no user to pick a next step.
STOP_TOOL_SCHEMA_SIMPLE = {
	"type": "function",
	"function": {
		"name": "stop",
		"description": "Stop the current session. Call when the request has been fulfilled or when you encounter a blocker that cannot be resolved without user input.",  # noqa: E501
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


def build_tool_schemas(mode: str, is_subagent: bool = False, backend=None, mode_is_auto: bool = True) -> list:
	"""Return list of tool schemas filtered by mode's allowed_actions.

	Args:
		mode: The AI mode (scan, chat, exploit). Unknown modes fall back to chat.
		is_subagent: If True, exclude change_mode and run_subagent (a subagent runs at its
			assigned mode, does not self-escalate, and must not spawn further subagents).
		backend: Optional interactivity backend for exclusion/extra tools. Every
			backend injects a `stop` tool via get_extra_tools (interactive backends a
			`stop` with `choices`, AutoBackend a choiceless one).
		mode_is_auto: Whether the session is in auto mode (vs a user-pinned mode).
			Gates `change_mode`: the model may self-escalate in an auto session or from
			a pinned ACTION mode, but a user-PINNED read-only `chat` must stay read-only,
			so `change_mode` is withheld there (the model can only suggest the user
			switches). An auto session that happens to resolve to chat KEEPS change_mode.

	Returns:
		List of OpenAI-format tool schema dicts.
	"""
	config = get_mode_config(mode)
	allowed_actions = config["allowed_actions"]
	excluded = set()
	if is_subagent:
		# A subagent runs at its assigned mode; it does not self-escalate and
		# cannot spawn further subagents (no nested subagents).
		excluded.update({"change_mode", "run_subagent"})
	# A user-pinned read-only chat cannot self-escape to an action mode.
	if not mode_is_auto and mode == "chat":
		excluded.add("change_mode")
	if backend is not None:
		excluded.update(backend.get_excluded_tools())
	schemas = [
		schema for tool_name, schema in TOOL_SCHEMAS.items()
		if TOOL_ACTION_MAP.get(tool_name) in allowed_actions
		and tool_name not in excluded
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
	# `stop` lives outside TOOL_SCHEMAS (injected per-backend); fall back to its schema so a
	# stringified `choices` array is coerced like any other object/array tool arg.
	schema = STOP_TOOL_SCHEMA if tool_name == "stop" else TOOL_SCHEMAS.get(tool_name, {})
	props = schema.get("function", {}).get("parameters", {}).get("properties", {})
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
