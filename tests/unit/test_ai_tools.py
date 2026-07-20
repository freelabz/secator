"""Tests for secator.ai.tools module."""
import unittest

from secator.definitions import ADDONS_ENABLED


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestToolSchemas(unittest.TestCase):
	"""Verify TOOL_SCHEMAS structure and content."""

	def test_tool_schemas_is_dict(self):
		from secator.ai.tools import TOOL_SCHEMAS
		self.assertIsInstance(TOOL_SCHEMAS, dict)

	def test_tool_schemas_has_six_tools(self):
		from secator.ai.tools import TOOL_SCHEMAS
		self.assertEqual(len(TOOL_SCHEMAS), 6)
		expected = {"run_task", "run_workflow", "run_shell", "query_workspace", "follow_up", "add_finding"}
		self.assertEqual(set(TOOL_SCHEMAS.keys()), expected)

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

	def test_follow_up_params(self):
		from secator.ai.tools import TOOL_SCHEMAS
		props = TOOL_SCHEMAS["follow_up"]["function"]["parameters"]["properties"]
		required = TOOL_SCHEMAS["follow_up"]["function"]["parameters"]["required"]
		self.assertIn("reason", props)
		self.assertIn("choices", props)
		self.assertEqual(props["reason"]["type"], "string")
		self.assertEqual(props["choices"]["type"], "array")
		self.assertIn("reason", required)
		self.assertNotIn("choices", required)

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

	def test_attack_mode_returns_all_tools(self):
		from secator.ai.tools import build_tool_schemas, TOOL_SCHEMAS
		schemas = build_tool_schemas("attack")
		self.assertEqual(len(schemas), 6)
		names = {s["function"]["name"] for s in schemas}
		self.assertEqual(names, set(TOOL_SCHEMAS.keys()))

	def test_chat_mode_excludes_task_and_workflow(self):
		from secator.ai.tools import build_tool_schemas
		schemas = build_tool_schemas("chat")
		names = {s["function"]["name"] for s in schemas}
		self.assertNotIn("run_task", names)
		self.assertNotIn("run_workflow", names)
		self.assertIn("query_workspace", names)
		self.assertIn("follow_up", names)
		self.assertIn("add_finding", names)
		self.assertIn("run_shell", names)

	def test_exploit_mode_excludes_follow_up_and_query(self):
		from secator.ai.tools import build_tool_schemas
		schemas = build_tool_schemas("exploit")
		names = {s["function"]["name"] for s in schemas}
		self.assertNotIn("follow_up", names)
		self.assertNotIn("query_workspace", names)
		self.assertIn("run_task", names)
		self.assertIn("run_workflow", names)
		self.assertIn("run_shell", names)
		self.assertIn("add_finding", names)

	def test_unknown_mode_falls_back_to_chat(self):
		from secator.ai.tools import build_tool_schemas
		chat_schemas = build_tool_schemas("chat")
		unknown_schemas = build_tool_schemas("nonexistent_mode")
		chat_names = {s["function"]["name"] for s in chat_schemas}
		unknown_names = {s["function"]["name"] for s in unknown_schemas}
		self.assertEqual(chat_names, unknown_names)

	def test_returns_list_of_dicts(self):
		from secator.ai.tools import build_tool_schemas
		schemas = build_tool_schemas("attack")
		self.assertIsInstance(schemas, list)
		for s in schemas:
			self.assertIsInstance(s, dict)
			self.assertEqual(s["type"], "function")


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

	def test_follow_up_conversion(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("follow_up", {"reason": "need guidance", "choices": ["a", "b"]})
		self.assertEqual(result["action"], "follow_up")
		self.assertEqual(result["reason"], "need guidance")
		self.assertEqual(result["choices"], ["a", "b"])

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


if __name__ == "__main__":
	unittest.main()
