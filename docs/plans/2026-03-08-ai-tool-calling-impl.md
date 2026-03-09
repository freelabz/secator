# Native Tool Calling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace fragile regex-based JSON parsing with litellm's native tool calling protocol, using 6 tool definitions that map 1:1 to existing action handlers.

**Architecture:** Define tool schemas in a new `secator/ai/tools.py` module. Modify `call_llm` to pass `tools` param and return structured `tool_calls`. Update `ChatHistory` to handle assistant+tool_calls and tool-role messages. Rewrite `_run_loop` to process `tool_calls` instead of `parse_actions`. Remove JSON parsing code and prompt TEMPLATE/EXAMPLES sections.

**Tech Stack:** litellm (tool calling), Python dataclasses, existing secator runner pipeline

**Test command:** `source /home/jahmyst/Workspace/secator/.venv/bin/activate && cd /home/jahmyst/Workspace/secator && python -m pytest tests/unit/TEST_FILE -v`

**Lint command:** `source /home/jahmyst/Workspace/secator/.venv/bin/activate && cd /home/jahmyst/Workspace/secator && secator test lint`

---

### Task 1: Create tool schema definitions (`secator/ai/tools.py`)

**Files:**
- Create: `secator/ai/tools.py`
- Test: `tests/unit/test_ai_tools.py`

**Step 1: Write the failing tests**

Create `tests/unit/test_ai_tools.py`:

```python
"""Tests for AI tool schema definitions."""
import pytest


class TestToolSchemas:
    """Test tool schema definitions."""

    def test_tool_schemas_is_dict(self):
        from secator.ai.tools import TOOL_SCHEMAS
        assert isinstance(TOOL_SCHEMAS, dict)

    def test_has_all_six_tools(self):
        from secator.ai.tools import TOOL_SCHEMAS
        expected = {"run_task", "run_workflow", "run_shell", "query_workspace", "follow_up", "add_finding"}
        assert set(TOOL_SCHEMAS.keys()) == expected

    def test_each_schema_has_openai_format(self):
        from secator.ai.tools import TOOL_SCHEMAS
        for name, schema in TOOL_SCHEMAS.items():
            assert schema["type"] == "function", f"{name} missing type=function"
            assert "function" in schema, f"{name} missing function key"
            func = schema["function"]
            assert func["name"] == name, f"{name} name mismatch"
            assert "description" in func, f"{name} missing description"
            assert "parameters" in func, f"{name} missing parameters"

    def test_run_task_schema_has_required_params(self):
        from secator.ai.tools import TOOL_SCHEMAS
        props = TOOL_SCHEMAS["run_task"]["function"]["parameters"]["properties"]
        assert "name" in props
        assert "targets" in props
        assert "opts" in props

    def test_run_workflow_schema_has_required_params(self):
        from secator.ai.tools import TOOL_SCHEMAS
        props = TOOL_SCHEMAS["run_workflow"]["function"]["parameters"]["properties"]
        assert "name" in props
        assert "targets" in props

    def test_run_shell_schema_has_command(self):
        from secator.ai.tools import TOOL_SCHEMAS
        props = TOOL_SCHEMAS["run_shell"]["function"]["parameters"]["properties"]
        assert "command" in props

    def test_query_workspace_schema_has_query_and_limit(self):
        from secator.ai.tools import TOOL_SCHEMAS
        props = TOOL_SCHEMAS["query_workspace"]["function"]["parameters"]["properties"]
        assert "query" in props
        assert "limit" in props

    def test_follow_up_schema_has_reason(self):
        from secator.ai.tools import TOOL_SCHEMAS
        props = TOOL_SCHEMAS["follow_up"]["function"]["parameters"]["properties"]
        assert "reason" in props
        assert "choices" in props

    def test_add_finding_schema_has_type(self):
        from secator.ai.tools import TOOL_SCHEMAS
        props = TOOL_SCHEMAS["add_finding"]["function"]["parameters"]["properties"]
        assert "_type" in props


class TestBuildToolSchemas:
    """Test build_tool_schemas filters by mode."""

    def test_attack_mode_returns_all_tools(self):
        from secator.ai.tools import build_tool_schemas
        tools = build_tool_schemas("attack")
        names = {t["function"]["name"] for t in tools}
        assert names == {"run_task", "run_workflow", "run_shell", "query_workspace", "follow_up", "add_finding"}

    def test_chat_mode_excludes_task_and_workflow(self):
        from secator.ai.tools import build_tool_schemas
        tools = build_tool_schemas("chat")
        names = {t["function"]["name"] for t in tools}
        assert "run_task" not in names
        assert "run_workflow" not in names
        assert "query_workspace" in names
        assert "run_shell" in names

    def test_exploiter_mode_excludes_follow_up_and_query(self):
        from secator.ai.tools import build_tool_schemas
        tools = build_tool_schemas("exploiter")
        names = {t["function"]["name"] for t in tools}
        assert "follow_up" not in names
        assert "query_workspace" not in names
        assert "run_task" in names
        assert "run_shell" in names

    def test_returns_list_of_dicts(self):
        from secator.ai.tools import build_tool_schemas
        tools = build_tool_schemas("attack")
        assert isinstance(tools, list)
        assert all(isinstance(t, dict) for t in tools)

    def test_unknown_mode_falls_back_to_chat(self):
        from secator.ai.tools import build_tool_schemas
        tools_chat = build_tool_schemas("chat")
        tools_unknown = build_tool_schemas("nonexistent")
        chat_names = {t["function"]["name"] for t in tools_chat}
        unknown_names = {t["function"]["name"] for t in tools_unknown}
        assert chat_names == unknown_names


class TestToolCallToAction:
    """Test converting tool_calls to action dicts."""

    def test_run_task_converts_to_action(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("run_task", {"name": "nmap", "targets": ["10.0.0.1"], "opts": {"ports": "80"}})
        assert action == {"action": "task", "name": "nmap", "targets": ["10.0.0.1"], "opts": {"ports": "80"}}

    def test_run_workflow_converts_to_action(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("run_workflow", {"name": "recon", "targets": ["example.com"]})
        assert action == {"action": "workflow", "name": "recon", "targets": ["example.com"]}

    def test_run_shell_converts_to_action(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("run_shell", {"command": "curl http://example.com"})
        assert action == {"action": "shell", "command": "curl http://example.com"}

    def test_query_workspace_converts_to_action(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("query_workspace", {"query": {"_type": "vulnerability"}, "limit": 10})
        assert action == {"action": "query", "query": {"_type": "vulnerability"}, "limit": 10}

    def test_follow_up_converts_to_action(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("follow_up", {"reason": "done", "choices": ["a", "b"]})
        assert action == {"action": "follow_up", "reason": "done", "choices": ["a", "b"]}

    def test_add_finding_converts_to_action(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("add_finding", {"_type": "vulnerability", "name": "SQLi", "severity": "high"})
        assert action == {"action": "add_finding", "_type": "vulnerability", "name": "SQLi", "severity": "high"}

    def test_unknown_tool_returns_none(self):
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("nonexistent", {})
        assert action is None
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_ai_tools.py -v`
Expected: FAIL (ModuleNotFoundError: No module named 'secator.ai.tools')

**Step 3: Write the implementation**

Create `secator/ai/tools.py`:

```python
"""Tool schema definitions for native LLM tool calling."""

# Map tool names to action types for dispatch
TOOL_ACTION_MAP = {
    "run_task": "task",
    "run_workflow": "workflow",
    "run_shell": "shell",
    "query_workspace": "query",
    "follow_up": "follow_up",
    "add_finding": "add_finding",
}

# Map action types back to tool names (for mode filtering)
ACTION_TOOL_MAP = {v: k for k, v in TOOL_ACTION_MAP.items()}

TOOL_SCHEMAS = {
    "run_task": {
        "type": "function",
        "function": {
            "name": "run_task",
            "description": "Run a secator security task (e.g. nmap, httpx, nuclei, ffuf). Prefer lightweight tasks (curl, nslookup, httpx) over heavy ones (nuclei, feroxbuster).",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Task name (e.g. nmap, httpx, nuclei, curl)"},
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of targets (hosts, URLs, IPs)"},
                    "opts": {"type": "object", "description": "Task options (e.g. ports, rate_limit, timeout, profiles)"},
                },
                "required": ["name", "targets"],
            },
        },
    },
    "run_workflow": {
        "type": "function",
        "function": {
            "name": "run_workflow",
            "description": "Run a secator workflow (multi-task pipeline). Only use when a comprehensive scan is needed or the user explicitly requests it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Workflow name"},
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of targets"},
                    "opts": {"type": "object", "description": "Workflow options (e.g. profiles)"},
                },
                "required": ["name", "targets"],
            },
        },
    },
    "run_shell": {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command. Use for curl, grep, jq, nslookup, or exploring truncated output files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute (no placeholders - all values must be concrete)"},
                },
                "required": ["command"],
            },
        },
    },
    "query_workspace": {
        "type": "function",
        "function": {
            "name": "query_workspace",
            "description": "Query the workspace for stored security findings using MongoDB-style queries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "object", "description": "MongoDB-style query filter (e.g. {\"_type\": \"vulnerability\", \"severity\": {\"$in\": [\"critical\", \"high\"]}})"},
                    "limit": {"type": "integer", "description": "Max results to return (default 100)", "default": 100},
                },
                "required": ["query"],
            },
        },
    },
    "follow_up": {
        "type": "function",
        "function": {
            "name": "follow_up",
            "description": "Ask the user for guidance on next steps. Use when: finding a vulnerability (ask what to do), unsure about direction, or task is complete. Choices must be concrete actions you can execute.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {"type": "string", "description": "Why follow-up is needed"},
                    "choices": {"type": "array", "items": {"type": "string"}, "description": "Optional concrete action choices (max 3). Only include if choices represent specific scans/queries/actions."},
                },
                "required": ["reason"],
            },
        },
    },
    "add_finding": {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": "Add a validated finding to the workspace. Only use when the user explicitly asks to add a finding, or you have concrete evidence from tool output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "_type": {"type": "string", "description": "Finding type: vulnerability, exploit, url, port, ip, subdomain, domain, certificate, tag"},
                },
                "required": ["_type"],
                "additionalProperties": True,
            },
        },
    },
}


def build_tool_schemas(mode: str) -> list:
    """Build list of tool schemas filtered by mode's allowed actions.

    Args:
        mode: One of "attack", "chat", "exploiter"

    Returns:
        List of OpenAI-format tool schema dicts
    """
    from secator.ai.prompts import get_mode_config
    config = get_mode_config(mode)
    allowed_actions = config.get("allowed_actions", [])
    tools = []
    for action_type in allowed_actions:
        tool_name = ACTION_TOOL_MAP.get(action_type)
        if tool_name and tool_name in TOOL_SCHEMAS:
            tools.append(TOOL_SCHEMAS[tool_name])
    return tools


def tool_call_to_action(tool_name: str, arguments: dict) -> dict | None:
    """Convert a tool call to an action dict for dispatch_action.

    Args:
        tool_name: Function name from tool_call
        arguments: Parsed arguments dict

    Returns:
        Action dict with 'action' key, or None if unknown tool
    """
    action_type = TOOL_ACTION_MAP.get(tool_name)
    if action_type is None:
        return None
    return {"action": action_type, **arguments}
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_ai_tools.py -v`
Expected: All PASS

**Step 5: Run lint**

Run: `secator test lint`
Expected: PASS

**Step 6: Commit**

```bash
git add secator/ai/tools.py tests/unit/test_ai_tools.py
git commit -m "feat(ai): add tool schema definitions for native tool calling"
```

---

### Task 2: Update `call_llm` to support tool calling

**Files:**
- Modify: `secator/ai/utils.py:90-147` (call_llm function)
- Test: `tests/unit/test_ai_utils.py` (TestCallLLM class)

**Step 1: Write the failing tests**

Add to `tests/unit/test_ai_utils.py`, inside `TestCallLLM`:

```python
def test_call_llm_with_tools_returns_tool_calls(self):
    """Test that call_llm passes tools and returns tool_calls."""
    from secator.ai.utils import call_llm
    from unittest.mock import patch, MagicMock

    # Mock a response with tool_calls
    mock_tool_call = MagicMock()
    mock_tool_call.id = "call_123"
    mock_tool_call.function.name = "run_shell"
    mock_tool_call.function.arguments = '{"command": "curl http://example.com"}'

    mock_message = MagicMock()
    mock_message.content = "Let me run a curl command."
    mock_message.tool_calls = [mock_tool_call]

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage = None

    with patch('secator.ai.utils.init_llm'), \
         patch('litellm.completion', return_value=mock_response) as mock_comp:
        tools = [{"type": "function", "function": {"name": "run_shell"}}]
        result = call_llm([{"role": "user", "content": "test"}], "gpt-4", tools=tools)

    mock_comp.assert_called_once()
    call_kwargs = mock_comp.call_args
    assert call_kwargs.kwargs.get("tools") == tools
    assert result["content"] == "Let me run a curl command."
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["id"] == "call_123"
    assert result["tool_calls"][0]["name"] == "run_shell"
    assert result["tool_calls"][0]["arguments"] == {"command": "curl http://example.com"}

def test_call_llm_without_tools_returns_empty_tool_calls(self):
    """Test that call_llm without tools returns empty tool_calls list."""
    from secator.ai.utils import call_llm
    from unittest.mock import patch, MagicMock

    mock_message = MagicMock()
    mock_message.content = "Hello"
    mock_message.tool_calls = None

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage = None

    with patch('secator.ai.utils.init_llm'), \
         patch('litellm.completion', return_value=mock_response):
        result = call_llm([{"role": "user", "content": "test"}], "gpt-4")

    assert result["tool_calls"] == []

def test_call_llm_tool_call_with_malformed_json(self):
    """Test that malformed tool call arguments are handled gracefully."""
    from secator.ai.utils import call_llm
    from unittest.mock import patch, MagicMock

    mock_tool_call = MagicMock()
    mock_tool_call.id = "call_bad"
    mock_tool_call.function.name = "run_shell"
    mock_tool_call.function.arguments = '{invalid json}'

    mock_message = MagicMock()
    mock_message.content = ""
    mock_message.tool_calls = [mock_tool_call]

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage = None

    with patch('secator.ai.utils.init_llm'), \
         patch('litellm.completion', return_value=mock_response):
        result = call_llm([{"role": "user", "content": "test"}], "gpt-4", tools=[{}])

    # Malformed arguments should result in empty dict
    assert result["tool_calls"][0]["arguments"] == {}
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_ai_utils.py::TestCallLLM::test_call_llm_with_tools_returns_tool_calls tests/unit/test_ai_utils.py::TestCallLLM::test_call_llm_without_tools_returns_empty_tool_calls tests/unit/test_ai_utils.py::TestCallLLM::test_call_llm_tool_call_with_malformed_json -v`
Expected: FAIL (call_llm doesn't accept tools param / doesn't return tool_calls)

**Step 3: Modify `call_llm` in `secator/ai/utils.py`**

Update the function signature and body at lines 90-147:

```python
def call_llm(
	messages: List[Dict],
	model: str,
	temperature: float = 0.7,
	api_base: Optional[str] = None,
	api_key: Optional[str] = None,
	max_retries: int = 3,
	tools: Optional[List[Dict]] = None,
) -> Dict:
	"""Call litellm completion and return response with usage and tool_calls.

	Args:
		messages: Chat messages in litellm format
		model: LLM model name
		temperature: Sampling temperature
		api_base: Optional API base URL
		api_key: Optional API key
		max_retries: Number of retries for transient errors
		tools: Optional list of tool schemas (OpenAI format)

	Returns:
		Dict with keys: content, usage, tool_calls
	"""
	import time
	import litellm

	init_llm(api_key=api_key)

	kwargs = dict(
		model=model,
		messages=messages,
		temperature=temperature,
		api_base=api_base,
	)
	if tools:
		kwargs["tools"] = tools

	retryable = (
		litellm.InternalServerError, litellm.RateLimitError,
		litellm.ServiceUnavailableError, litellm.APIConnectionError,
	)
	for attempt in range(1, max_retries + 1):
		try:
			response = litellm.completion(**kwargs)
			break
		except retryable as e:
			if attempt < max_retries:
				wait = 2 ** attempt
				console.print(Warning(
					message=f"LLM call failed (attempt {attempt}/{max_retries}): {e}. Retrying in {wait}s..."))
				time.sleep(wait)
			else:
				raise
		except litellm.AuthenticationError as e:
			console.print(Error(message=e))
			console.print(Error(
				message='Please set a valid API key with `secator config set addons.ai.api_key <KEY>`'
			))
			raise

	message = response.choices[0].message
	content = message.content or ""
	usage = None

	if hasattr(response, 'usage') and response.usage:
		try:
			cost = litellm.completion_cost(completion_response=response)
		except Exception:
			cost = None
		usage = {
			"tokens": response.usage.total_tokens,
			"cost": cost,
		}

	# Parse tool_calls
	parsed_tool_calls = []
	if message.tool_calls:
		for tc in message.tool_calls:
			try:
				arguments = json.loads(tc.function.arguments)
			except (json.JSONDecodeError, TypeError):
				arguments = {}
			parsed_tool_calls.append({
				"id": tc.id,
				"name": tc.function.name,
				"arguments": arguments,
			})

	return {"content": content, "usage": usage, "tool_calls": parsed_tool_calls}
```

Note: add `import json` at the top of the file if not already present (it is already imported).

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_ai_utils.py::TestCallLLM -v`
Expected: All PASS (both new and existing tests)

**Step 5: Run lint**

Run: `secator test lint`

**Step 6: Commit**

```bash
git add secator/ai/utils.py tests/unit/test_ai_utils.py
git commit -m "feat(ai): add tools parameter and tool_calls parsing to call_llm"
```

---

### Task 3: Update `ChatHistory` for tool calling messages

**Files:**
- Modify: `secator/ai/history.py:106-144` (ChatHistory methods)
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing tests**

Add to `tests/unit/test_ai_history.py`:

```python
class TestChatHistoryToolCalling:
    """Tests for tool calling message support."""

    def test_add_assistant_with_tool_calls(self):
        from secator.ai.history import ChatHistory
        history = ChatHistory()
        tool_calls = [
            {"id": "call_1", "type": "function", "function": {"name": "run_shell", "arguments": '{"command": "ls"}'}}
        ]
        history.add_assistant_with_tool_calls("reasoning text", tool_calls)
        msg = history.messages[-1]
        assert msg["role"] == "assistant"
        assert msg["content"] == "reasoning text"
        assert msg["tool_calls"] == tool_calls

    def test_add_assistant_with_tool_calls_no_content(self):
        from secator.ai.history import ChatHistory
        history = ChatHistory()
        tool_calls = [
            {"id": "call_1", "type": "function", "function": {"name": "run_shell", "arguments": '{"command": "ls"}'}}
        ]
        history.add_assistant_with_tool_calls(None, tool_calls)
        msg = history.messages[-1]
        assert msg["role"] == "assistant"
        assert msg.get("content") is None
        assert msg["tool_calls"] == tool_calls

    def test_add_tool_result(self):
        from secator.ai.history import ChatHistory
        history = ChatHistory()
        history.add_tool_result("call_1", "result content")
        msg = history.messages[-1]
        assert msg["role"] == "tool"
        assert msg["content"] == "result content"
        assert msg["tool_call_id"] == "call_1"

    def test_add_tool_result_preserves_order(self):
        from secator.ai.history import ChatHistory
        history = ChatHistory()
        history.add_tool_result("call_1", "result 1")
        history.add_tool_result("call_2", "result 2")
        assert history.messages[0]["tool_call_id"] == "call_1"
        assert history.messages[1]["tool_call_id"] == "call_2"

    def test_summarize_handles_tool_messages(self):
        """Summarization should work with tool_calls and tool messages in history."""
        from secator.ai.history import ChatHistory
        from unittest.mock import patch, MagicMock

        history = ChatHistory()
        history.model = "gpt-4"
        history.add_system("system prompt")
        history.add_user("initial request")
        # Add assistant with tool_calls
        tool_calls = [{"id": "c1", "type": "function", "function": {"name": "run_shell", "arguments": '{"command":"ls"}'}}]
        history.add_assistant_with_tool_calls("running ls", tool_calls)
        history.add_tool_result("c1", "file1.txt\nfile2.txt")
        history.add_assistant("Found 2 files.")

        # Mock should_compact to return True, and call_llm to return summary
        with patch.object(history, 'should_compact', return_value=True), \
             patch.object(history, 'count_tokens', return_value=1000), \
             patch('secator.ai.history.get_context_window', return_value=128000), \
             patch('secator.ai.utils.call_llm', return_value={"content": "Summary: found files"}):
            result = history.maybe_summarize("gpt-4")

        compacted, _, _ = result
        assert compacted is True
        # System and first user should be preserved
        assert history.messages[0]["role"] == "system"
        assert history.messages[1]["role"] == "user"
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_ai_history.py::TestChatHistoryToolCalling -v`
Expected: FAIL (add_assistant_with_tool_calls doesn't exist)

**Step 3: Add methods to `ChatHistory` in `secator/ai/history.py`**

Add after `add_assistant` method (line 140):

```python
    def add_assistant_with_tool_calls(self, content: str | None, tool_calls: list) -> None:
        """Add an assistant message that includes tool_calls.

        Args:
            content: Optional reasoning text (can be None)
            tool_calls: List of tool call dicts in OpenAI format
        """
        msg = {"role": "assistant", "tool_calls": tool_calls}
        if content is not None:
            msg["content"] = content
        self.messages.append(msg)

    def add_tool_result(self, tool_call_id: str, content: str) -> None:
        """Add a tool result message.

        Args:
            tool_call_id: The ID of the tool call this responds to
            content: The tool execution result
        """
        self.messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": content,
        })
```

Also update the existing `add_tool` method at line 142-143 — it currently doesn't include `tool_call_id`. Since `add_tool_result` replaces it, we can leave `add_tool` as-is for backward compat but prefer the new method.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_ai_history.py -v`
Expected: All PASS (both new and existing tests)

**Step 5: Run lint**

Run: `secator test lint`

**Step 6: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add tool calling message methods to ChatHistory"
```

---

### Task 4: Update `_run_loop` to process tool_calls

**Files:**
- Modify: `secator/tasks/ai.py:164-420` (_run_loop method)
- Modify: `secator/ai/actions.py` (remove group_actions)
- Test: `tests/unit/test_ai_integration.py`

This is the largest task. The core change: instead of `parse_actions(response)` we process `result["tool_calls"]` from `call_llm`.

**Step 1: Write the failing tests**

Replace `tests/unit/test_ai_integration.py` with tests for the new flow:

```python
"""Integration tests for tool calling flow."""
import json
import pytest
from unittest.mock import MagicMock, patch


class TestToolCallFlow:
    """Test tool_calls are converted to actions and dispatched."""

    def test_single_tool_call_dispatched(self):
        """Single tool_call → dispatch_action."""
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("run_shell", {"command": "curl http://example.com"})
        assert action == {"action": "shell", "command": "curl http://example.com"}

    def test_multiple_tool_calls_create_batch(self):
        """Multiple tool_calls in one response should be treated as parallel."""
        from secator.ai.tools import tool_call_to_action
        tool_calls = [
            {"id": "c1", "name": "run_task", "arguments": {"name": "nmap", "targets": ["10.0.0.1"]}},
            {"id": "c2", "name": "run_task", "arguments": {"name": "nmap", "targets": ["10.0.0.2"]}},
        ]
        actions = [tool_call_to_action(tc["name"], tc["arguments"]) for tc in tool_calls]
        assert len(actions) == 2
        assert all(a["action"] == "task" for a in actions)

    def test_unknown_tool_call_skipped(self):
        """Unknown tool name returns None."""
        from secator.ai.tools import tool_call_to_action
        result = tool_call_to_action("nonexistent_tool", {"arg": "val"})
        assert result is None

    def test_tool_call_to_action_preserves_all_fields(self):
        """All arguments are passed through to action dict."""
        from secator.ai.tools import tool_call_to_action
        action = tool_call_to_action("add_finding", {
            "_type": "vulnerability",
            "name": "SQLi",
            "severity": "critical",
            "matched_at": "http://example.com/login"
        })
        assert action["action"] == "add_finding"
        assert action["_type"] == "vulnerability"
        assert action["name"] == "SQLi"
        assert action["severity"] == "critical"
        assert action["matched_at"] == "http://example.com/login"


class TestToolCallHistoryFormat:
    """Test that tool results are added to history in correct format."""

    def test_assistant_tool_calls_format(self):
        """Assistant message with tool_calls has correct shape for litellm."""
        from secator.ai.history import ChatHistory
        history = ChatHistory()
        tool_calls = [{
            "id": "call_abc",
            "type": "function",
            "function": {"name": "run_shell", "arguments": '{"command": "ls"}'}
        }]
        history.add_assistant_with_tool_calls("thinking...", tool_calls)
        msg = history.messages[-1]
        assert msg["role"] == "assistant"
        assert msg["content"] == "thinking..."
        assert msg["tool_calls"] == tool_calls

    def test_tool_result_format(self):
        """Tool result message has correct shape for litellm."""
        from secator.ai.history import ChatHistory
        history = ChatHistory()
        history.add_tool_result("call_abc", '{"task":"nmap","status":"success","count":5}')
        msg = history.messages[-1]
        assert msg["role"] == "tool"
        assert msg["tool_call_id"] == "call_abc"
        assert "count" in msg["content"]
```

**Step 2: Run tests to verify they fail / pass**

Run: `python -m pytest tests/unit/test_ai_integration.py -v`
Expected: Should mostly pass since they test tools.py + history.py from previous tasks.

**Step 3: Modify `_run_loop` in `secator/tasks/ai.py`**

Key changes to the main loop (reference: `secator/tasks/ai.py:164-420`):

1. Import `build_tool_schemas` and `tool_call_to_action` from `secator.ai.tools`
2. Remove import of `group_actions` from `secator.ai.actions`
3. Build tool schemas at loop start: `tool_schemas = build_tool_schemas(mode)`
4. Pass `tools=tool_schemas` to `call_llm`
5. Replace `actions = parse_actions(response)` with tool_calls processing
6. Replace `group_actions(actions)` dispatch with: single tool_call → `dispatch_action`, multiple → `_run_batch`
7. Build litellm-format tool_calls for history (assistant message with tool_calls)
8. Add tool results as `tool` role messages instead of `user` messages
9. Display `content` as-is (remove `strip_json_from_response`)

The updated `_run_loop` core section (replacing lines ~218-391):

```python
        # Build tool schemas for this mode
        from secator.ai.tools import build_tool_schemas, tool_call_to_action
        tool_schemas = build_tool_schemas(mode)

        iteration = 0
        query_extensions = 0
        max_query_extensions = 3
        while iteration < max_iter:
            iteration += 1

            try:
                # Auto-summarize if token count exceeds threshold
                self.debug(f'[context] iteration {iteration}/{max_iter}, checking compaction...')
                summarized, old_tokens, new_tokens = history.maybe_summarize(
                    model, api_base=api_base, api_key=api_key)
                if summarized:
                    self.debug(f'[context] compacted: {old_tokens} -> {new_tokens} tokens')
                    yield Ai(
                        content=f"Chat history compacted: {old_tokens} -> {new_tokens} estimated tokens",
                        ai_type="chat_compacted",
                    )

                # Call LLM with tool schemas
                messages = history.to_messages(max_tokens_total=max_tokens_total)
                token_count = history.count_tokens(model)
                self.debug(f'[context] sending {token_count} tokens to LLM ({len(messages)} messages)')
                token_str = format_token_count(token_count, icon='arrow_up')
                msg = f"[bold orange3]{random.choice(LLM_SPINNER_MESSAGES)}[/] [gray42] • {token_str}[/]"
                with maybe_status(msg, spinner="dots"):
                    result = call_llm(messages, model, temp, api_base, api_key, tools=tool_schemas)
                response_content = result["content"]
                tool_calls = result.get("tool_calls", [])
                usage = result.get("usage", {})

                # Handle empty response
                if not response_content and not tool_calls:
                    yield Warning(message="LLM returned empty response")
                    continue

                # Decrypt response content
                if encryptor and response_content:
                    response_content = encryptor.decrypt(response_content)

                # Show response content (reasoning text)
                if response_content:
                    yield Ai(
                        content=response_content,
                        ai_type="response",
                        mode=mode,
                        model=model,
                        extra_data={
                            "iteration": iteration,
                            "max_iterations": max_iter,
                            "tokens": usage.get("tokens") if usage else None,
                            "cost": usage.get("cost") if usage else None,
                        },
                    )

                # Convert tool_calls to actions
                actions = []
                for tc in tool_calls:
                    arguments = tc["arguments"]
                    # Decrypt arguments
                    if encryptor:
                        from secator.ai.actions import _decrypt_dict
                        arguments = _decrypt_dict(arguments, encryptor)
                    action = tool_call_to_action(tc["name"], arguments)
                    if action:
                        actions.append((tc, action))
                    else:
                        yield Warning(message=f"Unknown tool call: {tc['name']}")

                # Build litellm-format tool_calls for history
                if tool_calls:
                    litellm_tool_calls = []
                    for tc in tool_calls:
                        litellm_tool_calls.append({
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc["arguments"], separators=(',', ':')),
                            }
                        })
                    history.add_assistant_with_tool_calls(response_content, litellm_tool_calls)
                else:
                    # Text-only response
                    if response_content:
                        history.add_assistant(response_content)

                # Execute actions
                if len(actions) > 0:
                    if len(actions) > 1:
                        yield Info(message=f"Executing {len(actions)} actions ...")
                    self.debug(json.dumps([a for _, a in actions], indent=4))

                follow_up_choices = None

                if len(actions) > 1:
                    # Multiple tool calls → parallel batch
                    action_list = [a for _, a in actions]
                    tc_list = [tc for tc, _ in actions]
                    action_iter = _run_batch(action_list, ctx)
                    batch_results = {}  # tc_id → results

                    for result_item in action_iter:
                        if isinstance(result_item, (Stat, Progress, State, Info)):
                            continue
                        if isinstance(result_item, Ai):
                            self.add_result(result_item)
                            if result_item.ai_type == "follow_up":
                                follow_up_choices = (result_item.extra_data or {}).get("choices", [])
                            if result_item.ai_type == "shell_output":
                                # Will be included in batch tool result
                                pass
                            continue
                        if isinstance(result_item, OutputType):
                            self.add_result(result_item, print=False)
                            result_item = result_item.toDict(exclude=list(INTERNAL_FIELDS))
                        if ctx.scope == "current":
                            ctx.results.append(result_item)

                    # Add tool results to history (one per tool call)
                    # For batch, we combine all results into each tool's result message
                    for i, (tc, action) in enumerate(actions):
                        action_name = action.get("name", action.get("action", ""))
                        tool_result = format_tool_result(action_name, "success", 0, [])
                        budget = history.get_action_budget(model)
                        tool_result = truncate_to_tokens(tool_result, budget, model)
                        tool_result = maybe_encrypt(tool_result, encryptor)
                        history.add_tool_result(tc["id"], tool_result)

                else:
                    # Single or no tool calls → sequential
                    for tc, action in actions:
                        action_type = action.get("action", "")
                        is_secator = action_type in ['task', 'workflow']
                        action_results = []
                        has_errors = False

                        for result_item in dispatch_action(action, ctx):
                            if isinstance(result_item, (Stat, Progress, State, Info)):
                                continue
                            if isinstance(result_item, Error):
                                has_errors = True
                            if isinstance(result_item, Ai):
                                self.add_result(result_item)
                                if result_item.ai_type == "follow_up":
                                    follow_up_choices = (result_item.extra_data or {}).get("choices", [])
                                if result_item.ai_type == "shell_output":
                                    action_results.append({"output": result_item.content})
                                continue
                            if isinstance(result_item, OutputType):
                                self.add_result(result_item)
                                result_item = result_item.toDict(exclude=list(INTERNAL_FIELDS))
                            action_results.append(result_item)
                            if ctx.scope == "current":
                                ctx.results.append(result_item)

                        # Build tool result for history
                        action_name = action.get("name", action_type)
                        tool_result = format_tool_result(
                            action_name,
                            "error" if has_errors else "success",
                            len(action_results),
                            action_results
                        )

                        # Apply token budget and truncation
                        budget = history.get_action_budget(model)
                        original_len = len(tool_result)
                        self.debug(f'[context] action "{action_type}" result: {len(action_results)} items, budget={budget} tokens')
                        if action_type in ("task", "workflow"):
                            fallback_path = Path(self.reports_folder) / "report.json" if self.reports_folder else None
                            tool_result = truncate_to_tokens(tool_result, budget, model, fallback_path=fallback_path)
                        elif action_type == "shell":
                            output_dir = Path(self.reports_folder) / ".outputs" if self.reports_folder else None
                            tool_result = truncate_to_tokens(
                                tool_result, budget, model,
                                output_dir=output_dir,
                                result_name="shell"
                            )
                        else:
                            tool_result = truncate_to_tokens(tool_result, budget, model)

                        truncated = "[TRUNCATED]" in tool_result
                        if truncated:
                            self.debug(f'[context] truncated: {original_len} -> {len(tool_result)} chars')

                        tool_result = maybe_encrypt(tool_result, encryptor)
                        history.add_tool_result(tc["id"], tool_result)

                if len(actions) > 0:
                    action_count = len(actions)
                    if action_count > 1:
                        yield Info(message=f"Executed {action_count} actions.")

                # If the last action was a query, allow one more iteration
                if actions and actions[-1][1].get("action") == "query" and query_extensions < max_query_extensions:
                    max_iter += 1
                    query_extensions += 1

                # Show menu if follow_up, no actions, or max_iter reached
                if follow_up_choices is not None or not actions or iteration == max_iter:
                    if not interactive:
                        return
                    if not follow_up_choices:
                        if iteration == max_iter:
                            yield Ai(content="Max iterations reached. What should I do next?", ai_type="follow_up")
                        elif not actions:
                            yield Ai(content="No actions to execute. What should I do next?", ai_type="follow_up")
                    result = self._prompt_and_redetect(
                        history, encryptor, max_iter, follow_up_choices or [], mode, api_base, api_key)
                    if result is None:
                        return
                    mode, max_iter, items = result
                    # Rebuild tool schemas if mode changed
                    tool_schemas = build_tool_schemas(mode)
                    yield from items
                    continue

                # STOP or CONTINUE
                stop_or_continue = "STOP or CONTINUE based on whether the initial user request has been fulfilled"
                continue_msg = format_continue(iteration, max_iter, stop_or_continue)
                history.add_user(maybe_encrypt(continue_msg, encryptor))

            except KeyboardInterrupt:
                if not interactive:
                    return
                yield Warning(message="Interrupted by user.")
                result = self._prompt_and_redetect(
                    history, encryptor, max_iter, [], mode, api_base, api_key)
                if result is None:
                    return
                mode, max_iter, items = result
                tool_schemas = build_tool_schemas(mode)
                yield from items
                continue

            except Exception as e:
                if isinstance(e, litellm.RateLimitError):
                    yield Warning(message="Rate limit exceeded - waiting 5s and retry in the next iteration")
                    iteration -= 1
                    sleep(5)
                    continue
                elif isinstance(e, litellm.AuthenticationError):
                    yield Error(message=str(e))
                    yield Error(
                        message='Please set a valid API key with `secator config set addons.ai.api_key <KEY>`'
                    )
                    return
                yield Error.from_exception(e)
                return

        yield Info(message=f"Reached max iterations ({max_iter})")
```

**Step 4: Run all tests**

Run: `python -m pytest tests/unit/test_ai_integration.py tests/unit/test_ai_tools.py tests/unit/test_ai_history.py tests/unit/test_ai_utils.py -v`
Expected: All PASS

**Step 5: Run lint**

Run: `secator test lint`

**Step 6: Commit**

```bash
git add secator/tasks/ai.py secator/ai/actions.py tests/unit/test_ai_integration.py
git commit -m "feat(ai): replace JSON parsing with native tool calling in main loop"
```

---

### Task 5: Simplify prompts (remove TEMPLATE/EXAMPLES)

**Files:**
- Modify: `secator/ai/prompts.py:14-128` (SYSTEM_ATTACK), `131-193` (SYSTEM_CHAT), `196-235` (SYSTEM_EXPLOITER)
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Update tests for new prompt structure**

In `tests/unit/test_ai_prompts.py`, update tests that check for TEMPLATE/EXAMPLES:

```python
def test_system_attack_has_no_template_section(self):
    from secator.ai.prompts import get_system_prompt
    prompt = get_system_prompt("attack")
    assert "### TEMPLATE" not in prompt

def test_system_attack_has_no_examples_section(self):
    from secator.ai.prompts import get_system_prompt
    prompt = get_system_prompt("attack")
    assert "### EXAMPLES" not in prompt

def test_system_chat_has_no_template_section(self):
    from secator.ai.prompts import get_system_prompt
    prompt = get_system_prompt("chat")
    assert "### TEMPLATE" not in prompt

def test_system_attack_still_has_persona(self):
    from secator.ai.prompts import get_system_prompt
    prompt = get_system_prompt("attack")
    assert "### PERSONA" in prompt

def test_system_attack_still_has_constraints(self):
    from secator.ai.prompts import get_system_prompt
    prompt = get_system_prompt("attack")
    assert "### CONSTRAINTS" in prompt
```

Also update existing tests that check for "action" in the prompt — those will need to be removed or adjusted since the TEMPLATE section is gone.

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_ai_prompts.py -v`
Expected: FAIL (TEMPLATE still in prompts)

**Step 3: Simplify prompt templates**

Update `SYSTEM_ATTACK` in `secator/ai/prompts.py` — remove everything from `### TEMPLATE` onward (lines ~66-128). Remove JSON-formatting constraints from CONSTRAINTS. Keep the "group"/"subagent" constraints since those are behavioral, but rephrase them to not reference JSON format:

Replace `SYSTEM_ATTACK` with:

```python
SYSTEM_ATTACK = Template("""
### PERSONA
You are an autonomous penetration testing agent conducting authorized security testing.

### ACTION
Analyze findings, identify exploitable vulnerabilities, execute attacks using secator runners or shell commands, and validate exploits with proof-of-concept.

### STEPS
1. Analyze targets and any existing findings from previous iterations
2. Plan an attack approach (for instance: "recon", "targeted attack", "exploitation", "post-exploitation")
3. Use your available tools to execute the plan
4. Analyze results from executed actions --> retry tasks that failed due to invalid options or parameters
5. Otherwise, repeat steps 3 and 4, being more specific with each iteration

### CONTEXT
$library_reference

Queryable types: $query_types
Query operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne

### CONSTRAINTS
- Keep responses concise: max 100 lines (unless user asks for more). Be direct and actionable.
- NEVER INVENT details, rely on the user data
- NEVER INVENT tool output
- ALWAYS USE options listed above for each task
- ALWAYS PREFER single Secator tasks over workflows/scans (less intrusive, more targeted)
- ALWAYS PREFER to use light tasks and commands (e.g: curl, nslookup, httpx, etc...) over noisy and long Secator tasks like nuclei, ffuf, or feroxbuster.
- ONLY use Secator workflows or scans when they truly fit the task at hand, or when the user explicitly requests "comprehensive", "full", or "deep" recon
- RETRY tasks that fails due to bad options, unsupported flags, or incorrect parameters, analyze the error, fix the options and re-run.
- NEVER use placeholders in options like "<target>", "<url>", "<your_wordlist>". All values must be concrete and usable. The user cannot interact with actions - they run autonomously.
- Use workspace queries to get historical data for context when needed
- PII data are encrypted as [HOST:xxxx] - use as-is (we'll decrypt it client-side)
- To use profiles, add "profiles": ["<profile1>", "<profile2>"] in opts
- When finding a vulnerability, ALWAYS ASK the user what to do with it using follow_up (choices are optional)
- When making vulnerability summaries, include the matched_at targets so we know what is impacted
- ONLY use add_finding when user explicitly requests it or you have validated the finding with concrete evidence
- When in doubt about what to do next, use the follow_up tool to ask the user for guidance
- When using follow_up:
	- ONLY include choices that represent concrete pentesting directions you can act on
	- Do NOT include choices for generic advice or things the user would do outside secator
	- MAXIMUM 3 well-thought options based on specific context
- TRUNCATED OUTPUT: When output shows [TRUNCATED] with a file path, the full data was saved. Use run_shell to explore it (grep, head, tail, jq).
- Call multiple tools at once to run independent actions in parallel
- When finding a HIGH or CRITICAL vulnerability that needs verification, use run_task to spawn an ai exploiter subagent with mode="exploiter", internal=true, and appropriate context
- Do NOT spawn AI subagents for simple tasks - only for complex exploitation verification
""")
```

Replace `SYSTEM_CHAT` with:

```python
SYSTEM_CHAT = Template("""
### PERSONA
You are an autonomous penetration testing agent conducting authorized security testing.

### ACTION
Answer user questions about their workspace by querying stored security data and providing clear analysis.

### STEPS
1. Analyze the user's question to determine what data is needed
2. Query the workspace for relevant findings using MongoDB queries
3. Analyze the returned results
4. Provide a clear markdown summary with actionable insights

### CONTEXT
$output_types_reference

Queryable types: $query_types
Query operators: $$in, $$regex, $$contains, $$gt, $$lt, $$ne

### CONSTRAINTS
- Keep responses concise: max 100 lines (unless user asks for more). Be direct and actionable.
- NEVER INVENT details, rely on the user data
- If a query fails, analyze the error and retry with corrected parameters. Do NOT give up after a single failure.
- If you hit a limit on the number of results, try to use more specific queries.
- NEVER use placeholders in queries. All values must be concrete and usable.
- ONLY use add_finding when user explicitly requests it
- When making vulnerability summaries, include the matched_at targets so we know what is impacted
- When in doubt about what to do next, use the follow_up tool
- When using follow_up:
	- Only include choices that represent concrete actions you can execute
	- Do NOT include choices for generic advice or things outside secator
	- MAXIMUM 3 well-thought options based on specific context
- TRUNCATED OUTPUT: When output shows [TRUNCATED] with a file path, use run_shell to explore it (grep, head, tail, jq).
""")
```

Replace `SYSTEM_EXPLOITER` with:

```python
SYSTEM_EXPLOITER = Template("""
### PERSONA
You are an exploitation verification specialist conducting authorized security testing.

### ACTION
Verify if a specific vulnerability is exploitable and document a working proof-of-concept.

### STEPS
1. Analyze the vulnerability details provided in your context
2. Research exploitation techniques for this vulnerability type
3. Attempt exploitation using appropriate tools or commands
4. Document each step: command used, expected vs actual output
5. Report success/failure with evidence

### CONTEXT
$library_reference

### CONSTRAINTS
- Focus ONLY on the vulnerability specified in your context
- Do NOT spawn other AI subagents
- Do NOT run broad scans or explore beyond scope
- Be methodical - try multiple techniques if first attempt fails
- Stop immediately if exploitation succeeds
- Stop if exploitation is not feasible after reasonable attempts
- NEVER INVENT output - only report actual results
- Keep responses concise and actionable
""")
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_ai_prompts.py -v`
Expected: PASS (after updating/removing tests that checked for old TEMPLATE/EXAMPLES content)

**Step 5: Run lint**

Run: `secator test lint`

**Step 6: Commit**

```bash
git add secator/ai/prompts.py tests/unit/test_ai_prompts.py
git commit -m "refactor(ai): simplify prompts by removing TEMPLATE/EXAMPLES sections"
```

---

### Task 6: Remove dead code

**Files:**
- Modify: `secator/ai/utils.py` (remove parse_actions, strip_json_from_response, _find_matching_bracket, _is_action_list)
- Modify: `secator/ai/actions.py` (remove group_actions)
- Remove/update: `tests/unit/test_ai_utils.py` (TestParseActions, TestFindMatchingBracket)
- Remove: `tests/unit/test_ai_group_actions.py`

**Step 1: Remove `parse_actions`, `strip_json_from_response`, `_find_matching_bracket`, `_is_action_list` from `secator/ai/utils.py`**

Delete lines 16-27 (`_find_matching_bracket`), 150-193 (`_is_action_list`, `parse_actions`), 196-224 (`strip_json_from_response`).

**Step 2: Remove `group_actions` from `secator/ai/actions.py`**

Delete lines 47-79 (`group_actions` function). Also remove the import of `group_actions` from `secator/tasks/ai.py` if still present.

**Step 3: Remove/update test files**

- In `tests/unit/test_ai_utils.py`: Remove `TestFindMatchingBracket` class and `TestParseActions` class entirely.
- Delete `tests/unit/test_ai_group_actions.py` entirely.

**Step 4: Run all tests**

Run: `python -m pytest tests/unit/ -k "ai" -v`
Expected: All PASS

**Step 5: Run lint**

Run: `secator test lint`

**Step 6: Commit**

```bash
git add secator/ai/utils.py secator/ai/actions.py tests/unit/test_ai_utils.py
git rm tests/unit/test_ai_group_actions.py
git commit -m "refactor(ai): remove dead JSON parsing and group_actions code"
```

---

### Task 7: Final integration test + full test suite

**Files:**
- Test: all `tests/unit/test_ai_*.py`

**Step 1: Run the full AI test suite**

Run: `python -m pytest tests/unit/test_ai_tools.py tests/unit/test_ai_utils.py tests/unit/test_ai_actions.py tests/unit/test_ai_history.py tests/unit/test_ai_prompts.py tests/unit/test_ai_integration.py tests/unit/test_ai_task_opts.py tests/unit/test_ai_handlers.py tests/unit/test_ai_safety.py -v`
Expected: All PASS

**Step 2: Run lint**

Run: `secator test lint`
Expected: PASS

**Step 3: Fix any failures**

Address any test failures or lint errors from the full suite.

**Step 4: Final commit if fixes were needed**

```bash
git add -A
git commit -m "fix(ai): address test/lint issues from tool calling migration"
```
