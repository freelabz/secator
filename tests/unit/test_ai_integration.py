"""Integration tests for tool calling flow."""
import json
import pytest


class TestToolCallFlow:
	"""Test tool_calls are converted to actions and dispatched."""

	def test_single_tool_call_dispatched(self):
		from secator.ai.tools import tool_call_to_action
		action = tool_call_to_action("run_shell", {"command": "curl http://example.com"})
		assert action == {"action": "shell", "command": "curl http://example.com"}

	def test_multiple_tool_calls_create_batch(self):
		from secator.ai.tools import tool_call_to_action
		tool_calls = [
			{"id": "c1", "name": "run_task", "arguments": {"name": "nmap", "targets": ["10.0.0.1"]}},
			{"id": "c2", "name": "run_task", "arguments": {"name": "nmap", "targets": ["10.0.0.2"]}},
		]
		actions = [tool_call_to_action(tc["name"], tc["arguments"]) for tc in tool_calls]
		assert len(actions) == 2
		assert all(a["action"] == "task" for a in actions)

	def test_unknown_tool_call_skipped(self):
		from secator.ai.tools import tool_call_to_action
		result = tool_call_to_action("nonexistent_tool", {"arg": "val"})
		assert result is None

	def test_tool_call_to_action_preserves_all_fields(self):
		from secator.ai.tools import tool_call_to_action
		action = tool_call_to_action("add_finding", {
			"_type": "vulnerability", "name": "SQLi",
			"severity": "critical", "matched_at": "http://example.com/login"
		})
		assert action["action"] == "add_finding"
		assert action["_type"] == "vulnerability"
		assert action["name"] == "SQLi"
		assert action["severity"] == "critical"


class TestToolCallHistoryFormat:
	"""Test tool results are added to history in correct format."""

	def test_assistant_tool_calls_format(self):
		from secator.ai.history import ChatHistory
		history = ChatHistory()
		tool_calls = [{
			"id": "call_abc", "type": "function",
			"function": {"name": "run_shell", "arguments": '{"command": "ls"}'}
		}]
		history.add_assistant_with_tool_calls("thinking...", tool_calls)
		msg = history.messages[-1]
		assert msg["role"] == "assistant"
		assert msg["content"] == "thinking..."
		assert msg["tool_calls"] == tool_calls

	def test_tool_result_format(self):
		from secator.ai.history import ChatHistory
		history = ChatHistory()
		history.add_tool_result("call_abc", '{"task":"nmap","status":"success","count":5}')
		msg = history.messages[-1]
		assert msg["role"] == "tool"
		assert msg["tool_call_id"] == "call_abc"
