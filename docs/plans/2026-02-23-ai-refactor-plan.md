# AI Task Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor ai.py from ~4000 lines to ~300 lines by extracting prompts, actions, and encryption into separate modules, using litellm's native message format with compact JSON.

**Architecture:** Split into focused modules (ai.py, ai_actions.py, ai_prompts.py, ai_encryption.py), refactor ai_history.py to use litellm format. Two modes only: attack and chat. All user messages as compact JSON, assistant messages as markdown + JSON.

**Tech Stack:** Python 3.9+, litellm, dataclasses

---

## Task 1: Create ai_encryption.py

Extract SensitiveDataEncryptor class from ai.py into its own module.

**Files:**
- Create: `secator/tasks/ai_encryption.py`
- Test: `tests/unit/test_ai_encryption.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_encryption.py
import unittest


class TestSensitiveDataEncryptor(unittest.TestCase):

    def test_encrypt_host(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "http://testphp.vulnweb.com/page"
        encrypted = encryptor.encrypt(original)

        self.assertIn("[HOST:", encrypted)
        self.assertNotIn("vulnweb.com", encrypted)

    def test_decrypt_restores_original(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor

        encryptor = SensitiveDataEncryptor()
        original = "http://example.com:8080/path?query=value"
        encrypted = encryptor.encrypt(original)
        decrypted = encryptor.decrypt(encrypted)

        self.assertEqual(decrypted, original)

    def test_decrypt_bare_hash(self):
        from secator.tasks.ai_encryption import SensitiveDataEncryptor
        import re

        encryptor = SensitiveDataEncryptor()
        original = "testphp.vulnweb.com"
        encrypted = encryptor.encrypt(original)

        match = re.search(r'\[HOST:([a-f0-9]+)\]', encrypted)
        self.assertIsNotNone(match)
        bare_hash = match.group(1)

        decrypted = encryptor.decrypt(bare_hash)
        self.assertEqual(decrypted, original)


if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_encryption.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secator.tasks.ai_encryption'"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai_encryption.py
"""Sensitive data encryption for AI prompts."""
import hashlib
import re
from typing import Dict, List

# PII patterns - order matters (specific before general)
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "host": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
}


class SensitiveDataEncryptor:
    """Encrypt sensitive data using SHA-256 hashing with salt."""

    def __init__(self, salt: str = "secator_pii_salt", custom_patterns: List[str] = None):
        self.salt = salt
        self.pii_map: Dict[str, str] = {}  # placeholder -> original
        self.hash_map: Dict[str, str] = {}  # bare hash -> original
        self.custom_patterns: List[re.Pattern] = []

        if custom_patterns:
            for pattern in custom_patterns:
                pattern = pattern.strip()
                if not pattern or pattern.startswith("#"):
                    continue
                try:
                    self.custom_patterns.append(re.compile(pattern))
                except re.error:
                    self.custom_patterns.append(re.compile(re.escape(pattern)))

    def _hash_value(self, value: str, pii_type: str) -> str:
        """Hash a sensitive value and return a placeholder."""
        hash_input = f"{self.salt}:{pii_type}:{value}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        placeholder = f"[{pii_type.upper()}:{hash_value}]"
        self.pii_map[placeholder] = value
        self.hash_map[hash_value] = value
        return placeholder

    def encrypt(self, text: str) -> str:
        """Encrypt all sensitive data in text."""
        if not text:
            return text

        result = text

        # Custom patterns first
        for i, pattern in enumerate(self.custom_patterns):
            for match in pattern.finditer(result):
                original = match.group()
                placeholder = self._hash_value(original, f"custom_{i}")
                result = result.replace(original, placeholder)

        # Built-in patterns
        for pii_type, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(result):
                original = match.group()
                placeholder = self._hash_value(original, pii_type)
                result = result.replace(original, placeholder)

        return result

    def decrypt(self, text: str) -> str:
        """Restore original sensitive values from placeholders."""
        result = text

        # Full placeholders [TYPE:hash]
        for placeholder, original in self.pii_map.items():
            result = result.replace(placeholder, original)

        # Without brackets TYPE:hash
        for placeholder, original in self.pii_map.items():
            no_brackets = placeholder[1:-1]
            result = result.replace(no_brackets, original)

        # Bare hashes
        for hash_value, original in self.hash_map.items():
            result = result.replace(hash_value, original)

        return result
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_encryption.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_encryption.py tests/unit/test_ai_encryption.py
git commit -m "refactor: extract SensitiveDataEncryptor to ai_encryption.py"
```

---

## Task 2: Create ai_prompts.py

Extract and simplify prompt templates into a focused module.

**Files:**
- Create: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_prompts.py
import unittest


class TestPrompts(unittest.TestCase):

    def test_system_attack_has_actions(self):
        from secator.tasks.ai_prompts import SYSTEM_ATTACK

        self.assertIn("task", SYSTEM_ATTACK)
        self.assertIn("workflow", SYSTEM_ATTACK)
        self.assertIn("shell", SYSTEM_ATTACK)
        self.assertIn("query", SYSTEM_ATTACK)
        self.assertIn("done", SYSTEM_ATTACK)

    def test_system_chat_has_query(self):
        from secator.tasks.ai_prompts import SYSTEM_CHAT

        self.assertIn("query", SYSTEM_CHAT)
        self.assertIn("done", SYSTEM_CHAT)

    def test_get_system_prompt_attack(self):
        from secator.tasks.ai_prompts import get_system_prompt

        prompt = get_system_prompt("attack")
        self.assertIn("task", prompt)
        self.assertIn("TOOLS:", prompt)

    def test_get_system_prompt_chat(self):
        from secator.tasks.ai_prompts import get_system_prompt

        prompt = get_system_prompt("chat")
        self.assertIn("query", prompt)

    def test_format_user_initial(self):
        from secator.tasks.ai_prompts import format_user_initial

        result = format_user_initial(["example.com"], "scan for vulns")
        self.assertIn("example.com", result)
        self.assertIn("scan for vulns", result)
        # Should be compact JSON
        self.assertNotIn("\n", result)

    def test_format_tool_result(self):
        from secator.tasks.ai_prompts import format_tool_result

        result = format_tool_result("nmap", "success", 5, [{"port": 80}])
        self.assertIn("nmap", result)
        self.assertIn("success", result)
        # Should be compact JSON
        self.assertNotIn("\n", result)


if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai_prompts.py
"""Compact prompt templates for AI task."""
import json
from typing import Any, List

# System prompt for attack mode (~400 tokens)
SYSTEM_ATTACK = """Security testing assistant. Execute actions against provided targets.

RESPONSE FORMAT:
1. Brief reasoning (2-3 sentences max)
2. JSON array of actions

ACTIONS:
- task: {{"action":"task","name":"<tool>","targets":[...],"opts":{{}}}}
- workflow: {{"action":"workflow","name":"<name>","targets":[...]}}
- shell: {{"action":"shell","command":"<cmd>"}}
- query: {{"action":"query","type":"<output_type>","filter":{{}}}}
- done: {{"action":"done","reason":"<why>"}}

RULES:
- One action array per response
- Never invent tool output
- Use query to check results before concluding
- Targets are encrypted as [HOST:xxxx] - use as-is

TOOLS: {tools}
WORKFLOWS: {workflows}"""

# System prompt for chat mode (~200 tokens)
SYSTEM_CHAT = """Security assistant for workspace queries and analysis.

RESPONSE FORMAT: Markdown explanation, then optional JSON action.

ACTIONS:
- query: {{"action":"query","type":"<type>","filter":{{}}}}
- done: {{"action":"done"}}

Answer questions using workspace data. Use query action to fetch data."""


def get_tools_list() -> str:
    """Get comma-separated list of available tasks."""
    try:
        from secator.loader import discover_tasks
        tasks = discover_tasks()
        return ", ".join(sorted(t.__name__ for t in tasks))
    except Exception:
        return "nmap, httpx, nuclei, ffuf, katana, subfinder"


def get_workflows_list() -> str:
    """Get comma-separated list of available workflows."""
    try:
        from secator.loader import get_configs_by_type
        workflows = get_configs_by_type('workflow')
        return ", ".join(sorted(w.name for w in workflows))
    except Exception:
        return "host_recon, subdomain_recon, url_crawl"


def get_system_prompt(mode: str) -> str:
    """Get system prompt for mode with tools/workflows filled in."""
    if mode == "attack":
        return SYSTEM_ATTACK.format(
            tools=get_tools_list(),
            workflows=get_workflows_list()
        )
    elif mode == "chat":
        return SYSTEM_CHAT
    else:
        return SYSTEM_CHAT


def format_user_initial(targets: List[str], instructions: str) -> str:
    """Format initial user message as compact JSON."""
    return json.dumps({
        "targets": targets,
        "instructions": instructions or "Conduct security testing."
    }, separators=(',', ':'))


def format_tool_result(name: str, status: str, count: int, sample: Any) -> str:
    """Format tool result as compact JSON."""
    return json.dumps({
        "task": name,
        "status": status,
        "count": count,
        "sample": sample[:3] if isinstance(sample, list) else sample
    }, separators=(',', ':'), default=str)


def format_continue(iteration: int, max_iterations: int) -> str:
    """Format continue message as compact JSON."""
    return json.dumps({
        "iteration": iteration,
        "max": max_iterations,
        "instruction": "continue"
    }, separators=(',', ':'))
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "refactor: create ai_prompts.py with compact JSON templates"
```

---

## Task 3: Create ai_actions.py

Extract action handlers into a focused module.

**Files:**
- Create: `secator/tasks/ai_actions.py`
- Test: `tests/unit/test_ai_actions.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_actions.py
import unittest
from unittest.mock import Mock, patch


class TestActionDispatch(unittest.TestCase):

    def test_dispatch_task_action(self):
        from secator.tasks.ai_actions import dispatch_action

        action = {
            "action": "task",
            "name": "httpx",
            "targets": ["example.com"],
            "opts": {}
        }
        ctx = Mock()
        ctx.dry_run = True
        ctx.encryptor = None

        results = list(dispatch_action(action, ctx))

        # Should yield Info about dry run
        self.assertTrue(any("dry run" in str(r).lower() or "httpx" in str(r).lower() for r in results))

    def test_dispatch_done_action(self):
        from secator.tasks.ai_actions import dispatch_action

        action = {"action": "done", "reason": "completed testing"}
        ctx = Mock()
        ctx.dry_run = False
        ctx.encryptor = None

        results = list(dispatch_action(action, ctx))

        self.assertTrue(len(results) > 0)

    def test_dispatch_unknown_action(self):
        from secator.tasks.ai_actions import dispatch_action

        action = {"action": "unknown_action"}
        ctx = Mock()
        ctx.encryptor = None

        results = list(dispatch_action(action, ctx))

        # Should yield warning about unknown action
        self.assertTrue(any("unknown" in str(r).lower() for r in results))


if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_actions.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai_actions.py
"""Action handlers for AI task."""
import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

from secator.output_types import Ai, Error, Info, Warning


@dataclass
class ActionContext:
    """Shared context for action execution."""
    targets: List[str]
    model: str
    encryptor: Any = None
    dry_run: bool = False
    auto_yes: bool = False
    workspace_id: Optional[str] = None
    attack_context: Dict = field(default_factory=dict)


def dispatch_action(action: Dict, ctx: ActionContext) -> Generator:
    """Route action to appropriate handler."""
    action_type = action.get("action", "")

    handlers = {
        "task": _handle_task,
        "workflow": _handle_workflow,
        "shell": _handle_shell,
        "query": _handle_query,
        "done": _handle_done,
    }

    handler = handlers.get(action_type)
    if handler:
        yield from handler(action, ctx)
    else:
        yield Warning(message=f"Unknown action: {action_type}")


def _handle_task(action: Dict, ctx: ActionContext) -> Generator:
    """Execute a secator task."""
    name = action.get("name", "")
    targets = action.get("targets", ctx.targets)
    opts = action.get("opts", {})

    # Decrypt targets if encryptor present
    if ctx.encryptor:
        targets = [ctx.encryptor.decrypt(t) for t in targets]

    if ctx.dry_run:
        yield Info(message=f"[DRY RUN] Would run task: {name} on {targets}")
        return

    yield Ai(content=f"Running task: {name}", ai_type="task", extra_data={"targets": targets})

    try:
        from secator.runners import Task
        task_cls = Task.get_task_class(name)

        run_opts = {
            "print_item": False,
            "print_line": False,
            "print_cmd": False,
            "print_progress": False,
            "sync": True,
            **opts,
        }

        task = task_cls(targets, **run_opts)
        results = []
        for item in task:
            results.append(item)
            yield item

        # Track in attack context
        ctx.attack_context.setdefault("successful_attacks", []).append({
            "type": "task",
            "name": name,
            "targets": targets,
            "result_count": len(results)
        })

    except Exception as e:
        yield Error(message=f"Task {name} failed: {e}")
        ctx.attack_context.setdefault("failed_attacks", []).append({
            "type": "task",
            "name": name,
            "error": str(e)
        })


def _handle_workflow(action: Dict, ctx: ActionContext) -> Generator:
    """Execute a secator workflow."""
    name = action.get("name", "")
    targets = action.get("targets", ctx.targets)

    if ctx.encryptor:
        targets = [ctx.encryptor.decrypt(t) for t in targets]

    if ctx.dry_run:
        yield Info(message=f"[DRY RUN] Would run workflow: {name} on {targets}")
        return

    yield Ai(content=f"Running workflow: {name}", ai_type="workflow", extra_data={"targets": targets})

    try:
        from secator.runners import Workflow
        workflow = Workflow(targets, name=name, sync=True)
        results = []
        for item in workflow:
            results.append(item)
            yield item

        ctx.attack_context.setdefault("successful_attacks", []).append({
            "type": "workflow",
            "name": name,
            "targets": targets,
            "result_count": len(results)
        })

    except Exception as e:
        yield Error(message=f"Workflow {name} failed: {e}")


def _handle_shell(action: Dict, ctx: ActionContext) -> Generator:
    """Execute a shell command."""
    command = action.get("command", "")

    if ctx.encryptor:
        command = ctx.encryptor.decrypt(command)

    if ctx.dry_run:
        yield Info(message=f"[DRY RUN] Would run: {command}")
        return

    yield Ai(content=f"Running: {command}", ai_type="shell")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout or result.stderr or "(no output)"
        yield Ai(content=output[:2000], ai_type="shell_output")

        ctx.attack_context.setdefault("successful_attacks", []).append({
            "type": "shell",
            "command": command,
            "output": output[:500]
        })

    except Exception as e:
        yield Error(message=f"Shell command failed: {e}")


def _handle_query(action: Dict, ctx: ActionContext) -> Generator:
    """Query workspace for findings."""
    query_filter = action.get("filter", {})
    output_type = action.get("type", "")

    if output_type:
        query_filter["_type"] = output_type

    # Decrypt query values
    if ctx.encryptor:
        query_filter = _decrypt_dict(query_filter, ctx.encryptor)

    yield Ai(
        content=f"Query: {json.dumps(query_filter, separators=(',',':'))}",
        ai_type="query"
    )

    if not ctx.workspace_id:
        yield Warning(message="No workspace available for query")
        return

    try:
        from secator.query import QueryEngine
        engine = QueryEngine(ctx.workspace_id)
        results = engine.search(query_filter, limit=50)
        yield Info(message=f"Query returned {len(results)} results")

        # Store for next iteration
        ctx.attack_context["_query_results"] = results

    except Exception as e:
        yield Error(message=f"Query failed: {e}")


def _handle_done(action: Dict, ctx: ActionContext) -> Generator:
    """Handle completion."""
    reason = action.get("reason", "completed")
    yield Ai(content=f"Done: {reason}", ai_type="stopped")
    ctx.attack_context["_should_stop"] = True


def _decrypt_dict(d: Dict, encryptor) -> Dict:
    """Recursively decrypt all string values in a dict."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = encryptor.decrypt(v)
        elif isinstance(v, dict):
            result[k] = _decrypt_dict(v, encryptor)
        elif isinstance(v, list):
            result[k] = [encryptor.decrypt(i) if isinstance(i, str) else i for i in v]
        else:
            result[k] = v
    return result
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_actions.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_actions.py tests/unit/test_ai_actions.py
git commit -m "refactor: create ai_actions.py with action handlers"
```

---

## Task 4: Refactor ai_history.py for litellm format

Simplify ChatHistory to be a thin wrapper around litellm's message list.

**Files:**
- Modify: `secator/tasks/ai_history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_history.py
import unittest


class TestChatHistory(unittest.TestCase):

    def test_add_system(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_system("You are an assistant.")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "system")

    def test_add_user_json(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_user('{"targets":["example.com"]}')

        messages = history.to_messages()
        self.assertEqual(messages[0]["role"], "user")
        self.assertIn("targets", messages[0]["content"])

    def test_add_assistant(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("Analysis here.\n\n```json\n[{\"action\":\"done\"}]\n```")

        messages = history.to_messages()
        self.assertEqual(messages[0]["role"], "assistant")

    def test_to_messages_returns_list(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_system("sys")
        history.add_user("user")
        history.add_assistant("assistant")

        messages = history.to_messages()
        self.assertIsInstance(messages, list)
        self.assertEqual(len(messages), 3)

    def test_clear(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_user("test")
        history.clear()

        self.assertEqual(len(history.to_messages()), 0)


if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_history.py -v`
Expected: Some tests fail (add_system, clear not implemented)

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai_history.py
"""Chat history management for AI task - litellm format."""
from dataclasses import dataclass, field
from typing import Callable, Dict, List


@dataclass
class ChatHistory:
    """Manages chat history in litellm message format."""

    messages: List[Dict[str, str]] = field(default_factory=list)

    def add_system(self, content: str) -> None:
        """Add a system message."""
        self.messages.append({"role": "system", "content": content})

    def add_user(self, content: str) -> None:
        """Add a user message (should be JSON)."""
        self.messages.append({"role": "user", "content": content})

    def add_assistant(self, content: str) -> None:
        """Add an assistant message (markdown + JSON)."""
        self.messages.append({"role": "assistant", "content": content})

    def to_messages(self) -> List[Dict[str, str]]:
        """Return messages for litellm completion()."""
        return self.messages.copy()

    def clear(self) -> None:
        """Clear all messages."""
        self.messages = []

    def summarize(self, summarizer: Callable, keep_last: int = 4) -> None:
        """Summarize older messages, keeping recent ones.

        Args:
            summarizer: Function that takes messages and returns summary
            keep_last: Number of recent messages to keep verbatim
        """
        if len(self.messages) <= keep_last:
            return

        to_summarize = self.messages[:-keep_last]
        to_keep = self.messages[-keep_last:]

        summary = summarizer(to_summarize)

        self.messages = [
            {"role": "system", "content": f"Previous context:\n{summary}"}
        ] + to_keep
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_history.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_history.py tests/unit/test_ai_history.py
git commit -m "refactor: simplify ai_history.py for litellm format"
```

---

## Task 5: Create new ai.py (~300 lines)

Rewrite the main Ai task class using the new modules.

**Files:**
- Create: `secator/tasks/ai_new.py` (initially, then rename)
- Test: `tests/unit/test_ai_new.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_new.py
import unittest
from unittest.mock import Mock, patch


class TestAiTask(unittest.TestCase):

    def test_ai_task_has_required_attributes(self):
        from secator.tasks.ai_new import ai

        self.assertTrue(hasattr(ai, 'opts'))
        self.assertIn('prompt', ai.opts)
        self.assertIn('mode', ai.opts)
        self.assertIn('model', ai.opts)

    def test_parse_actions_single(self):
        from secator.tasks.ai_new import parse_actions

        response = 'Analysis.\n\n[{"action":"done","reason":"complete"}]'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action"], "done")

    def test_parse_actions_multiple(self):
        from secator.tasks.ai_new import parse_actions

        response = 'Running scans.\n\n[{"action":"task","name":"nmap"},{"action":"task","name":"httpx"}]'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 2)

    def test_parse_actions_code_block(self):
        from secator.tasks.ai_new import parse_actions

        response = 'Analysis.\n\n```json\n[{"action":"done"}]\n```'
        actions = parse_actions(response)

        self.assertEqual(len(actions), 1)

    def test_strip_json_from_response(self):
        from secator.tasks.ai_new import strip_json_from_response

        response = 'Found login page.\n\n[{"action":"task","name":"nuclei"}]'
        text = strip_json_from_response(response)

        self.assertIn("Found login page", text)
        self.assertNotIn("nuclei", text)


if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_new.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

Create `secator/tasks/ai_new.py` with ~300 lines:

```python
# secator/tasks/ai_new.py
"""AI-powered penetration testing task - simplified implementation."""
import json
import logging
import re
from typing import Any, Dict, Generator, List, Optional

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Ai, Error, Info, Warning, Vulnerability
from secator.runners import PythonRunner

from secator.tasks.ai_actions import ActionContext, dispatch_action
from secator.tasks.ai_encryption import SensitiveDataEncryptor
from secator.tasks.ai_history import ChatHistory
from secator.tasks.ai_prompts import (
    get_system_prompt,
    format_user_initial,
    format_tool_result,
    format_continue,
)

logger = logging.getLogger(__name__)


def parse_actions(response: str) -> List[Dict]:
    """Extract JSON action array from LLM response."""
    # Try code block first
    match = re.search(r'```(?:json)?\s*(\[[\s\S]*?\])\s*```', response)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try raw JSON array
    match = re.search(r'\[[\s\S]*?"action"[\s\S]*?\]', response)
    if match:
        try:
            # Find matching brackets
            text = response[match.start():]
            depth = 0
            end = 0
            for i, c in enumerate(text):
                if c == '[':
                    depth += 1
                elif c == ']':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            return json.loads(text[:end])
        except json.JSONDecodeError:
            pass

    return []


def strip_json_from_response(text: str) -> str:
    """Remove JSON blocks, keep only text/reasoning."""
    if not text:
        return ""

    # Remove code blocks
    text = re.sub(r'```(?:json)?\s*\[[\s\S]*?\]\s*```', '', text)

    # Remove raw JSON arrays with actions
    result = []
    i = 0
    while i < len(text):
        if text[i] == '[' and '"action"' in text[i:i+100]:
            depth = 0
            while i < len(text):
                if text[i] == '[':
                    depth += 1
                elif text[i] == ']':
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
        else:
            result.append(text[i])
            i += 1

    return ''.join(result).strip()


def call_llm(
    messages: List[Dict],
    model: str,
    temperature: float = 0.7,
    api_base: str = None,
) -> Dict:
    """Call litellm completion and return response with usage."""
    import litellm

    response = litellm.completion(
        model=model,
        messages=messages,
        temperature=temperature,
        api_base=api_base,
    )

    content = response.choices[0].message.content
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

    return {"content": content, "usage": usage}


@task()
class ai(PythonRunner):
    """AI-powered penetration testing assistant."""

    output_types = [Vulnerability, Info, Warning, Error, Ai]
    tags = ["ai", "analysis", "pentest"]
    input_types = []
    install_cmd = "pip install litellm"
    default_inputs = ''

    opts = {
        "prompt": {"type": str, "default": "", "short": "p", "help": "Natural language prompt"},
        "mode": {"type": str, "default": "", "help": "Mode: attack or chat (auto-detected)"},
        "model": {"type": str, "default": CONFIG.ai.default_model, "help": "LLM model"},
        "api_base": {"type": str, "default": CONFIG.ai.api_base, "help": "API base URL"},
        "sensitive": {"is_flag": True, "default": True, "help": "Encrypt sensitive data"},
        "max_iterations": {"type": int, "default": 10, "help": "Max attack iterations"},
        "temperature": {"type": float, "default": 0.7, "help": "LLM temperature"},
        "dry_run": {"is_flag": True, "default": False, "help": "Show actions without executing"},
        "yes": {"is_flag": True, "default": False, "short": "y", "help": "Auto-accept prompts"},
        "verbose": {"is_flag": True, "default": False, "short": "v", "help": "Verbose output"},
    }

    def yielder(self) -> Generator:
        """Execute AI task."""
        try:
            import litellm  # noqa
        except ImportError:
            yield Error(message="litellm required. Install: pip install litellm")
            return

        prompt = self.run_opts.get("prompt", "")
        mode = self.run_opts.get("mode", "") or self._detect_mode(prompt)
        model = self.run_opts.get("model")
        targets = self.inputs

        yield Info(message=f"Using model: {model}, mode: {mode}")

        # Initialize encryptor
        encryptor = None
        if self.run_opts.get("sensitive", True):
            encryptor = SensitiveDataEncryptor()

        # Route to mode
        if mode == "attack":
            yield from self._run_attack(prompt, targets, model, encryptor)
        else:
            yield from self._run_chat(prompt, targets, model, encryptor)

    def _detect_mode(self, prompt: str) -> str:
        """Detect mode from prompt keywords."""
        attack_keywords = ["attack", "exploit", "scan", "test", "pentest", "hack"]
        prompt_lower = prompt.lower()

        if any(kw in prompt_lower for kw in attack_keywords):
            return "attack"
        return "chat"

    def _run_attack(
        self,
        prompt: str,
        targets: List[str],
        model: str,
        encryptor: Optional[SensitiveDataEncryptor],
    ) -> Generator:
        """Run attack loop."""
        max_iterations = self.run_opts.get("max_iterations", 10)
        temperature = self.run_opts.get("temperature", 0.7)
        api_base = self.run_opts.get("api_base")
        dry_run = self.run_opts.get("dry_run", False)
        verbose = self.run_opts.get("verbose", False)

        # Initialize
        history = ChatHistory()
        history.add_system(get_system_prompt("attack"))

        # Build initial user message (compact JSON)
        user_msg = format_user_initial(targets, prompt)
        if encryptor:
            user_msg = encryptor.encrypt(user_msg)
        history.add_user(user_msg)

        # Show prompt
        yield Ai(content=prompt or "Starting attack...", ai_type="prompt")

        # Build context
        ctx = ActionContext(
            targets=targets,
            model=model,
            encryptor=encryptor,
            dry_run=dry_run,
            auto_yes=self.run_opts.get("yes", False),
            workspace_id=self.context.get("workspace_id") if self.context else None,
        )

        for iteration in range(max_iterations):
            yield Info(message=f"Iteration {iteration + 1}/{max_iterations}")

            try:
                # Call LLM
                result = call_llm(
                    messages=history.to_messages(),
                    model=model,
                    temperature=temperature,
                    api_base=api_base,
                )

                response = result["content"]
                usage = result.get("usage", {})

                # Decrypt response
                if encryptor:
                    response = encryptor.decrypt(response)

                # Parse actions
                actions = parse_actions(response)

                # Show response (strip JSON for display)
                display_text = response if verbose else strip_json_from_response(response)
                if display_text:
                    yield Ai(
                        content=display_text,
                        ai_type="response",
                        mode="attack",
                        model=model,
                        extra_data={
                            "iteration": iteration + 1,
                            "tokens": usage.get("tokens"),
                            "cost": usage.get("cost"),
                        },
                    )

                # Add to history
                history.add_assistant(response)

                if not actions:
                    yield Warning(message="Could not parse actions")
                    continue

                # Execute actions
                for action in actions:
                    action_type = action.get("action", "")

                    # Check for done
                    if action_type == "done":
                        yield from dispatch_action(action, ctx)
                        yield Info(message="Attack completed")
                        return

                    yield from dispatch_action(action, ctx)

                    # Build tool result for history
                    tool_result = format_tool_result(
                        action.get("name", action_type),
                        "success",
                        len(ctx.attack_context.get("successful_attacks", [])),
                        []
                    )
                    if encryptor:
                        tool_result = encryptor.encrypt(tool_result)
                    history.add_user(tool_result)

                # Add continue message
                continue_msg = format_continue(iteration + 1, max_iterations)
                if encryptor:
                    continue_msg = encryptor.encrypt(continue_msg)
                history.add_user(continue_msg)

            except Exception as e:
                yield Error(message=f"Iteration failed: {e}")
                logger.exception("Attack iteration error")

        yield Info(message=f"Reached max iterations ({max_iterations})")

    def _run_chat(
        self,
        prompt: str,
        targets: List[str],
        model: str,
        encryptor: Optional[SensitiveDataEncryptor],
    ) -> Generator:
        """Run chat mode for Q&A."""
        temperature = self.run_opts.get("temperature", 0.7)
        api_base = self.run_opts.get("api_base")

        history = ChatHistory()
        history.add_system(get_system_prompt("chat"))

        # Build user message
        user_msg = format_user_initial(targets, prompt)
        if encryptor:
            user_msg = encryptor.encrypt(user_msg)
        history.add_user(user_msg)

        yield Ai(content=prompt, ai_type="prompt")

        try:
            result = call_llm(
                messages=history.to_messages(),
                model=model,
                temperature=temperature,
                api_base=api_base,
            )

            response = result["content"]
            usage = result.get("usage", {})

            if encryptor:
                response = encryptor.decrypt(response)

            yield Ai(
                content=response,
                ai_type="response",
                mode="chat",
                model=model,
                extra_data={
                    "tokens": usage.get("tokens"),
                    "cost": usage.get("cost"),
                },
            )

        except Exception as e:
            yield Error(message=f"Chat failed: {e}")
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_new.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_new.py tests/unit/test_ai_new.py
git commit -m "feat: create simplified ai_new.py (~300 lines)"
```

---

## Task 6: Integration and switchover

Replace old ai.py with new implementation.

**Files:**
- Rename: `secator/tasks/ai.py` -> `secator/tasks/ai_old.py`
- Rename: `secator/tasks/ai_new.py` -> `secator/tasks/ai.py`
- Update: imports in any dependent files
- Test: Run existing tests

**Step 1: Backup old implementation**

```bash
mv secator/tasks/ai.py secator/tasks/ai_old.py
```

**Step 2: Move new implementation**

```bash
mv secator/tasks/ai_new.py secator/tasks/ai.py
```

**Step 3: Run all tests**

Run: `python -m pytest tests/unit/test_ai*.py -v`
Expected: All tests pass

**Step 4: Run integration test**

Run: `secator x ai -t example.com -p "scan for open ports" --dry-run`
Expected: Shows actions without executing

**Step 5: Commit**

```bash
git add secator/tasks/ai.py secator/tasks/ai_old.py
git commit -m "refactor: replace ai.py with simplified implementation"
```

---

## Task 7: Cleanup and final tests

Remove old implementation and ensure all tests pass.

**Files:**
- Delete: `secator/tasks/ai_old.py`
- Update: `tests/unit/test_ai_safety.py` (update imports if needed)

**Step 1: Verify all functionality works**

Run:
```bash
secator x ai -t testphp.vulnweb.com -p "scan for vulnerabilities" --mode attack --max-iterations 3 --dry-run
secator x ai -p "what tools are available" --mode chat
```

**Step 2: Remove old implementation**

```bash
rm secator/tasks/ai_old.py
```

**Step 3: Run full test suite**

Run: `secator test unit --test test_ai`
Expected: All tests pass

**Step 4: Final commit**

```bash
git add -A
git commit -m "refactor: complete ai.py simplification - removed old implementation"
```

---

## Summary

After completing all tasks:

| Module | Lines | Purpose |
|--------|-------|---------|
| ai.py | ~300 | Main Ai Task, run loop |
| ai_actions.py | ~200 | Action handlers |
| ai_prompts.py | ~100 | Compact prompt templates |
| ai_encryption.py | ~80 | SensitiveDataEncryptor |
| ai_history.py | ~50 | ChatHistory (litellm format) |

**Total: ~730 lines** (vs ~4000 original)

Key improvements:
- Two modes only: attack and chat
- litellm native message format
- Compact JSON (no whitespace)
- Assistant responses: markdown + JSON
- Proper encryption/decryption flow
- Token/cost tracking on all calls
