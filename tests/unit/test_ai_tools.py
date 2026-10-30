"""Tests for secator.ai.tools module."""
import unittest

from secator.definitions import ADDONS_ENABLED


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestToolSchemas(unittest.TestCase):
	"""Verify TOOL_SCHEMAS structure and content."""

	def test_tool_schemas_is_dict(self):
		from secator.ai.tools import TOOL_SCHEMAS
		self.assertIsInstance(TOOL_SCHEMAS, dict)

	def test_tool_schemas_has_builtin_tools(self):
		from secator.ai.tools import TOOL_SCHEMAS
		# `stop` is NOT in TOOL_SCHEMAS — it is injected per-backend via get_extra_tools.
		# Built-ins are always present; dynamic (autoloaded) tools may add more, so this is a
		# subset check, not an exact-set/count assertion.
		builtins = {"run_task", "run_workflow", "run_shell", "query_workspace", "read_file", "write_file",
		            "fetch_url", "screenshot", "update_plan", "web_search", "list_runners",
		            "run_subagent", "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive",
		            "mark_vuln_exploit_failed", "update_finding", "change_mode"}
		self.assertTrue(builtins.issubset(set(TOOL_SCHEMAS.keys())))

	def test_tool_schemas_openai_format(self):
		from secator.ai.tools import TOOL_SCHEMAS
		for name, schema in TOOL_SCHEMAS.items():
			self.assertEqual(schema["type"], "function", f"{name} missing type=function")
			func = schema["function"]
			self.assertIn("name", func, f"{name} missing function.name")
			self.assertIn("description", func, f"{name} missing function.description")
			self.assertIn("parameters", func, f"{name} missing function.parameters")
			params = func["parameters"]
			self.assertEqual(params["type"], "object", f"{name} params type != object")
			self.assertIn("properties", params, f"{name} missing properties")
			self.assertIn("required", params, f"{name} missing required")

	def test_run_task_params(self):
		from secator.ai.tools import TOOL_SCHEMAS
		props = TOOL_SCHEMAS["run_task"]["function"]["parameters"]["properties"]
		required = TOOL_SCHEMAS["run_task"]["function"]["parameters"]["required"]
		self.assertIn("name", props)
		self.assertIn("targets", props)
		self.assertIn("opts", props)
		self.assertEqual(props["name"]["type"], "string")
		self.assertEqual(props["targets"]["type"], "array")
		self.assertEqual(props["opts"]["type"], "object")
		self.assertIn("name", required)
		self.assertIn("targets", required)
		self.assertNotIn("opts", required)

	def test_run_workflow_params(self):
		from secator.ai.tools import TOOL_SCHEMAS
		props = TOOL_SCHEMAS["run_workflow"]["function"]["parameters"]["properties"]
		required = TOOL_SCHEMAS["run_workflow"]["function"]["parameters"]["required"]
		self.assertIn("name", props)
		self.assertIn("targets", props)
		self.assertIn("opts", props)
		self.assertIn("name", required)
		self.assertIn("targets", required)
		self.assertNotIn("opts", required)

	def test_run_shell_params(self):
		from secator.ai.tools import TOOL_SCHEMAS
		props = TOOL_SCHEMAS["run_shell"]["function"]["parameters"]["properties"]
		required = TOOL_SCHEMAS["run_shell"]["function"]["parameters"]["required"]
		self.assertIn("command", props)
		self.assertEqual(props["command"]["type"], "string")
		self.assertIn("command", required)

	def test_query_workspace_params(self):
		from secator.ai.tools import TOOL_SCHEMAS
		props = TOOL_SCHEMAS["query_workspace"]["function"]["parameters"]["properties"]
		required = TOOL_SCHEMAS["query_workspace"]["function"]["parameters"]["required"]
		self.assertIn("query", props)
		self.assertIn("limit", props)
		self.assertEqual(props["query"]["type"], "object")
		self.assertEqual(props["limit"]["type"], "integer")
		self.assertEqual(props["limit"].get("default"), 100)
		self.assertIn("query", required)
		self.assertNotIn("limit", required)

	def test_interactive_stop_params(self):
		# The interactive `stop` carries reason + optional choices/multiple.
		from secator.ai.tools import STOP_TOOL_SCHEMA
		props = STOP_TOOL_SCHEMA["function"]["parameters"]["properties"]
		required = STOP_TOOL_SCHEMA["function"]["parameters"]["required"]
		self.assertIn("reason", props)
		self.assertIn("choices", props)
		self.assertIn("multiple", props)
		self.assertEqual(props["reason"]["type"], "string")
		self.assertEqual(props["choices"]["type"], "array")
		self.assertIn("reason", required)
		self.assertNotIn("choices", required)

	def test_simple_stop_has_no_choices(self):
		# The non-interactive (AutoBackend) `stop` is definitive: reason only, no choices.
		from secator.ai.tools import STOP_TOOL_SCHEMA_SIMPLE
		props = STOP_TOOL_SCHEMA_SIMPLE["function"]["parameters"]["properties"]
		self.assertIn("reason", props)
		self.assertNotIn("choices", props)
		self.assertNotIn("multiple", props)

	def test_add_finding_params(self):
		from secator.ai.tools import TOOL_SCHEMAS
		props = TOOL_SCHEMAS["add_finding"]["function"]["parameters"]["properties"]
		required = TOOL_SCHEMAS["add_finding"]["function"]["parameters"]["required"]
		params = TOOL_SCHEMAS["add_finding"]["function"]["parameters"]
		self.assertIn("_type", props)
		self.assertEqual(props["_type"]["type"], "string")
		self.assertIn("_type", required)
		self.assertTrue(params.get("additionalProperties", False))


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBuildToolSchemas(unittest.TestCase):
	"""Verify build_tool_schemas filters by mode."""

	def test_scan_mode_returns_allowed_tools(self):
		from secator.ai.tools import build_tool_schemas, TOOL_SCHEMAS, TOOL_ACTION_MAP
		from secator.ai.prompts import get_mode_config
		schemas = build_tool_schemas("scan")
		names = {s["function"]["name"] for s in schemas}
		allowed = set(get_mode_config("scan")["allowed_actions"])
		# every returned tool maps to an allowed action, and every built-in tool whose action is
		# allowed is returned (dynamic tools may add to both sides, so compare on this invariant).
		self.assertTrue(all(TOOL_ACTION_MAP.get(n) in allowed for n in names))
		builtin_allowed = {n for n, sc in TOOL_SCHEMAS.items() if TOOL_ACTION_MAP.get(n) in allowed}
		self.assertTrue(builtin_allowed.issubset(names))

	def test_chat_mode_excludes_task_and_workflow(self):
		from secator.ai.tools import build_tool_schemas
		schemas = build_tool_schemas("chat")
		names = {s["function"]["name"] for s in schemas}
		# chat is strictly read-only (#1469): no escalation (run_task/run_workflow),
		# no shell, no finding writes — it keeps query + the same-mode run_subagent helper.
		self.assertNotIn("run_task", names)
		self.assertNotIn("run_workflow", names)
		self.assertNotIn("run_shell", names)
		self.assertNotIn("add_finding", names)
		self.assertIn("query_workspace", names)
		self.assertIn("run_subagent", names)

	def test_exploit_mode_includes_query(self):
		from secator.ai.tools import build_tool_schemas
		schemas = build_tool_schemas("exploit")
		names = {s["function"]["name"] for s in schemas}
		self.assertIn("query_workspace", names)
		self.assertIn("run_task", names)
		self.assertIn("run_workflow", names)
		self.assertIn("run_shell", names)
		self.assertIn("add_finding", names)
		# exploit can delegate a subagent just like scan (the tool docstring even says
		# "hand a confirmed vuln to an exploit subagent"); without this, the model tried
		# the run_task(name="ai") workaround, hit the guard that points at run_subagent,
		# and dead-ended because the tool wasn't exposed in this mode.
		self.assertIn("run_subagent", names)

	def test_contribute_mode_authors_code_not_findings(self):
		"""contribute is a directly-selected code-authoring mode: it RUNS runners
		(task/workflow/shell), reads/edits files (read_file/write_file), searches, and
		delegates to subagents — but it writes NO findings (add_finding/mark_vuln_*) and
		cannot change_mode (terminal, host-side mode)."""
		from secator.ai.tools import build_tool_schemas
		names = {s["function"]["name"] for s in build_tool_schemas("contribute")}
		for t in ("run_task", "run_workflow", "run_shell", "read_file", "write_file",
		          "run_subagent", "web_search", "fetch_url", "update_plan"):
			self.assertIn(t, names, t)
		for t in ("add_finding", "mark_vuln_exploited", "mark_vuln_false_positive",
		          "mark_vuln_exploit_failed", "update_finding", "change_mode", "screenshot"):
			self.assertNotIn(t, names, t)

	def test_monitor_mode_tool_surface(self):
		"""Monitor can read, re-run the originating check, retire a non-reproducing vuln and
		fix metadata — but never add findings, mark exploited, delegate or self-escalate."""
		from secator.ai.tools import build_tool_schemas
		from secator.ai.interactivity import CLIBackend
		names = {s["function"]["name"] for s in build_tool_schemas("monitor", backend=CLIBackend())}
		for present in ["query_workspace", "run_task", "run_workflow", "run_shell",
		                "mark_vuln_false_positive", "update_finding", "stop"]:
			self.assertIn(present, names)
		for absent in ["add_finding", "mark_vuln_exploited", "mark_vuln_exploit_failed",
		               "run_subagent", "change_mode"]:
			self.assertNotIn(absent, names)

	def test_research_mode_full_active_surface_minus_change_mode(self):
		"""research is a directly-selected terminal action mode: it gets the full active
		surface (shell to stand up a lab, web_search to find PoCs, run_subagent for
		adversarial fan-out, add_finding to record the Exploit, read/write_file) but NOT
		change_mode — it already has the top surface and must not escalate/de-escalate."""
		from secator.ai.tools import build_tool_schemas
		names = {s["function"]["name"] for s in build_tool_schemas("research")}
		for t in ("run_shell", "web_search", "run_subagent", "add_finding", "run_task",
		          "run_workflow", "query_workspace", "mark_vuln_exploited", "read_file", "write_file"):
			self.assertIn(t, names, t)
		self.assertNotIn("change_mode", names)

	def test_change_mode_gated_by_pin(self):
		"""change_mode lets the model self-escalate in an AUTO session or from a pinned
		action mode, but a user-PINNED read-only chat must stay read-only (tool withheld),
		and a subagent never self-escalates."""
		from secator.ai.tools import build_tool_schemas

		def names(**kw):
			return {s["function"]["name"] for s in build_tool_schemas(**kw)}
		self.assertIn("change_mode", names(mode="chat", mode_is_auto=True))       # auto chat
		self.assertNotIn("change_mode", names(mode="chat", mode_is_auto=False))   # pinned read-only chat
		self.assertIn("change_mode", names(mode="scan", mode_is_auto=False))    # pinned scan
		self.assertIn("change_mode", names(mode="exploit", mode_is_auto=False))   # pinned exploit
		self.assertNotIn("change_mode", names(mode="scan", is_subagent=True))   # subagent

	def test_subagent_excludes_run_subagent(self):
		"""A subagent has no run_subagent tool (no nested subagents); a non-subagent keeps it."""
		from secator.ai.tools import build_tool_schemas
		from secator.ai.interactivity import AutoBackend

		def names(**kw):
			return {s["function"]["name"] for s in build_tool_schemas(**kw)}
		self.assertNotIn("run_subagent", names(mode="scan", is_subagent=True, backend=AutoBackend()))
		self.assertIn("run_subagent", names(mode="scan", is_subagent=False, backend=AutoBackend()))

	def test_unknown_mode_falls_back_to_chat(self):
		from secator.ai.tools import build_tool_schemas
		chat_schemas = build_tool_schemas("chat")
		unknown_schemas = build_tool_schemas("nonexistent_mode")
		chat_names = {s["function"]["name"] for s in chat_schemas}
		unknown_names = {s["function"]["name"] for s in unknown_schemas}
		self.assertEqual(chat_names, unknown_names)

	def test_returns_list_of_dicts(self):
		from secator.ai.tools import build_tool_schemas
		schemas = build_tool_schemas("scan")
		self.assertIsInstance(schemas, list)
		for s in schemas:
			self.assertIsInstance(s, dict)
			self.assertEqual(s["type"], "function")

	def test_stop_injected_for_every_backend(self):
		"""`stop` is the single end-of-turn signal in EVERY mode — every backend injects
		it via get_extra_tools. Interactive backends inject the choices-capable stop; the
		AutoBackend a choiceless (definitive) one."""
		from secator.ai.tools import build_tool_schemas
		from secator.ai.interactivity import CLIBackend, RemoteBackend, TUIBackend, AutoBackend
		for backend in (CLIBackend(), RemoteBackend(), TUIBackend()):
			stop = next(s for s in build_tool_schemas("scan", backend=backend)
			            if s["function"]["name"] == "stop")
			self.assertIn("choices", stop["function"]["parameters"]["properties"])
		auto_stop = next(s for s in build_tool_schemas("scan", backend=AutoBackend())
		                 if s["function"]["name"] == "stop")
		self.assertNotIn("choices", auto_stop["function"]["parameters"]["properties"])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestToolCallToAction(unittest.TestCase):
	"""Verify tool_call_to_action conversion."""

	def test_run_task_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("run_task", {"name": "nmap", "targets": ["127.0.0.1"]})
		self.assertEqual(result["action"], "task")
		self.assertEqual(result["name"], "nmap")
		self.assertEqual(result["targets"], ["127.0.0.1"])

	def test_run_workflow_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("run_workflow", {"name": "recon", "targets": ["example.com"]})
		self.assertEqual(result["action"], "workflow")
		self.assertEqual(result["name"], "recon")

	def test_run_shell_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("run_shell", {"command": "whoami"})
		self.assertEqual(result["action"], "shell")
		self.assertEqual(result["command"], "whoami")

	def test_query_workspace_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("query_workspace", {"query": {"_type": "vulnerability"}, "limit": 50})
		self.assertEqual(result["action"], "query")
		self.assertEqual(result["query"], {"_type": "vulnerability"})
		self.assertEqual(result["limit"], 50)

	def test_stop_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("stop", {"reason": "need guidance", "choices": ["a", "b"]})
		self.assertEqual(result["action"], "stop")
		self.assertEqual(result["reason"], "need guidance")
		self.assertEqual(result["choices"], ["a", "b"])

	def test_uuid_arg_is_normalized_to_underscore(self):
		# Models often drop the leading underscore (`uuid` instead of `_uuid`); the
		# converter normalizes it so finding tools don't error "requires `_uuid`".
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("mark_vuln_exploited", {"uuid": "u1", "poc": "# poc"})
		self.assertEqual(result["_uuid"], "u1")
		self.assertNotIn("uuid", result)

	def test_existing_underscore_uuid_wins_over_uuid(self):
		# If the model already sent `_uuid`, don't clobber it with a stray `uuid`.
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("mark_vuln_exploited", {"_uuid": "right", "uuid": "wrong", "poc": "x"})
		self.assertEqual(result["_uuid"], "right")

	def test_add_finding_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("add_finding", {"_type": "vulnerability", "name": "SQLi", "severity": "high"})
		self.assertEqual(result["action"], "add_finding")
		self.assertEqual(result["_type"], "vulnerability")
		self.assertEqual(result["name"], "SQLi")
		self.assertEqual(result["severity"], "high")

	def test_unknown_tool_returns_none(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("nonexistent_tool", {"foo": "bar"})
		self.assertIsNone(result)

	def test_non_dict_arguments_rejected(self):
		"""Non-object arguments (a bare JSON int/array/string) reject cleanly to None
		instead of raising AttributeError on .items() and aborting the loop."""
		from secator.ai.tools import tool_call_to_action
		for bad in (12345, ["nmap", "10.0.0.1"], "just a string"):
			self.assertIsNone(tool_call_to_action("run_task", bad))

	def test_stop_with_empty_args_is_valid(self):
		"""`stop` ends a turn and its `reason` is optional, so a bare stop() with empty
		or no args must produce a valid action — not get bounced as 'empty arguments'
		(which left the model nagging instead of stopping)."""
		from secator.ai.tools import tool_call_to_action
		for empty in ({}, None):
			action = tool_call_to_action("stop", empty)
			self.assertIsNotNone(action, empty)
			self.assertEqual(action["action"], "stop")
		# the exemption is stop-only: other tools with empty args still reject
		self.assertIsNone(tool_call_to_action("run_task", {}))
		self.assertIsNone(tool_call_to_action("query_workspace", None))

	def test_change_mode_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("change_mode", {"mode": "scan", "reason": "need to scan"})
		self.assertEqual(result["action"], "change_mode")
		self.assertEqual(result["mode"], "scan")

@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestCoerceStringifiedArgs(unittest.TestCase):
	"""Models sometimes serialize object/array params as JSON strings even though
	the schema says object/array — coerce them back at the tool-call boundary."""

	def test_stringified_opts_and_targets_coerced(self):
		from secator.ai.tools import coerce_stringified_args
		args = coerce_stringified_args("run_task", {
			"name": "nmap",
			"targets": '["10.0.0.1", "10.0.0.2"]',       # array sent as string
			"opts": '{"session_name": "scan-x", "top_ports": 100}',  # object sent as string
		})
		self.assertEqual(args["targets"], ["10.0.0.1", "10.0.0.2"])
		self.assertEqual(args["opts"], {"session_name": "scan-x", "top_ports": 100})

	def test_stringified_query_coerced(self):
		from secator.ai.tools import coerce_stringified_args
		args = coerce_stringified_args("query_workspace", {"query": '{"_type": "url"}'})
		self.assertEqual(args["query"], {"_type": "url"})

	def test_already_typed_args_untouched(self):
		from secator.ai.tools import coerce_stringified_args
		args = coerce_stringified_args("run_task", {"name": "nmap", "targets": ["a"], "opts": {"x": 1}})
		self.assertEqual(args["targets"], ["a"])
		self.assertEqual(args["opts"], {"x": 1})

	def test_malformed_json_left_as_is(self):
		from secator.ai.tools import coerce_stringified_args
		args = coerce_stringified_args("run_task", {"name": "nmap", "opts": "not json"})
		self.assertEqual(args["opts"], "not json")  # left for the handler to reject cleanly

	def test_scalar_string_params_not_coerced(self):
		"""A string-typed param (e.g. run_shell.command) must stay a string."""
		from secator.ai.tools import coerce_stringified_args
		args = coerce_stringified_args("run_shell", {"command": '{"looks": "like json"}'})
		self.assertEqual(args["command"], '{"looks": "like json"}')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestToolRegistry(unittest.TestCase):
	"""The TOOLS registry is the single source of truth; adding a tool is one class.

	These guard the drift that used to rot the 5 hand-synced surfaces (schema,
	action map, per-mode allowed_actions, dispatch table, permission auto-allow).
	"""

	def test_names_and_actions_unique(self):
		from secator.ai.tools import TOOLS
		names = [t.name for t in TOOLS]
		actions = [t.action for t in TOOLS]
		self.assertEqual(len(names), len(set(names)), "duplicate tool name")
		self.assertEqual(len(actions), len(set(actions)), "duplicate tool action")

	def test_derived_maps_match_registry(self):
		from secator.ai.tools import TOOLS, TOOL_ACTION_MAP, TOOL_SCHEMAS, STOP_TOOL_SCHEMA
		# TOOL_ACTION_MAP covers every tool (incl. injected stop).
		self.assertEqual(TOOL_ACTION_MAP, {t.name: t.action for t in TOOLS})
		# TOOL_SCHEMAS excludes injected tools (stop is injected via the backend).
		self.assertEqual(set(TOOL_SCHEMAS), {t.name for t in TOOLS if not t.injected})
		self.assertNotIn("stop", TOOL_SCHEMAS)
		self.assertIn("stop", TOOL_ACTION_MAP)
		self.assertEqual(STOP_TOOL_SCHEMA["function"]["name"], "stop")

	def test_every_handler_exists(self):
		from secator.ai import actions
		from secator.ai.tools import TOOLS
		for t in TOOLS:
			self.assertTrue(hasattr(actions, t.handler), f"{t.name} handler {t.handler} missing")

	def test_mode_exposure_matches_allowed_actions(self):
		"""CONSISTENCY GUARD: a tool exposed in a mode (`tool.modes`) must be in that
		mode's `allowed_actions`, and every tool-type `allowed_action` must be exposed —
		so tool exposure (schemas) and the authz gate can't silently drift apart."""
		from secator.ai.tools import TOOLS, TOOLS_BY_ACTION
		from secator.ai.prompts import MODES
		for mode, cfg in MODES.items():
			exposed = {t.action for t in TOOLS if mode in t.modes}
			allowed_tool_actions = {a for a in cfg["allowed_actions"] if a in TOOLS_BY_ACTION}
			self.assertEqual(
				exposed, allowed_tool_actions,
				f"mode '{mode}': tool.modes exposure {exposed} != tool-type allowed_actions {allowed_tool_actions}"
			)

	def test_auto_allow_only_control_and_finding_actions(self):
		"""task/workflow/shell must NOT be auto-allowed (they get name/scope rule checks);
		everything else the model can call is auto-allowed at the action-type layer."""
		from secator.ai.tools import TOOLS_BY_ACTION
		for act in ("task", "workflow", "shell"):
			self.assertFalse(TOOLS_BY_ACTION[act].auto_allow, f"{act} should not be auto-allowed")
		for act in ("subagent", "stop", "change_mode", "query",
		            "add_finding", "mark_vuln_exploited", "mark_vuln_false_positive",
		            "mark_vuln_exploit_failed", "update_finding"):
			self.assertTrue(TOOLS_BY_ACTION[act].auto_allow, f"{act} should be auto-allowed")


if __name__ == "__main__":
	unittest.main()
