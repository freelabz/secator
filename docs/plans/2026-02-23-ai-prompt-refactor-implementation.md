# AI Prompt Structure Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor AI attack mode with clear prompt structure, chat history with summarization, and single encryption gate.

**Architecture:** Create `ChatHistory` class for message management and summarization, `PromptBuilder` class for assembling prompts. Move encryption to single edge point before LLM calls. Integrate with existing `_mode_attack` loop.

**Tech Stack:** Python dataclasses, LiteLLM for summarization, existing SensitiveDataEncryptor

---

### Task 1: Create ChatHistory class with basic message management

**Files:**
- Create: `secator/tasks/ai_history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_history.py
import unittest

class TestChatHistory(unittest.TestCase):

    def test_add_assistant_message(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("I will run nmap")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "assistant")
        self.assertEqual(messages[0]["content"], "I will run nmap")

    def test_add_tool_message(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_tool("nmap output: port 80 open")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "tool")
        self.assertEqual(messages[0]["content"], "nmap output: port 80 open")

    def test_add_user_message(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_user("Focus on web vulnerabilities")

        messages = history.to_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        self.assertEqual(messages[0]["content"], "Focus on web vulnerabilities")

    def test_multiple_messages_preserve_order(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("Running nmap")
        history.add_tool("Port 80 open")
        history.add_assistant("Found web server")

        messages = history.to_messages()
        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[0]["role"], "assistant")
        self.assertEqual(messages[1]["role"], "tool")
        self.assertEqual(messages[2]["role"], "assistant")
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_history.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secator.tasks.ai_history'"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai_history.py
"""Chat history management for AI attack mode."""
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class ChatHistory:
    """Manages chat history with role-based messages."""

    messages: List[Dict[str, str]] = field(default_factory=list)

    def add_assistant(self, content: str) -> None:
        """Add an assistant message."""
        self.messages.append({"role": "assistant", "content": content})

    def add_tool(self, content: str) -> None:
        """Add a tool response message."""
        self.messages.append({"role": "tool", "content": content})

    def add_user(self, content: str) -> None:
        """Add a user message."""
        self.messages.append({"role": "user", "content": content})

    def to_messages(self) -> List[Dict[str, str]]:
        """Return all messages as a list."""
        return self.messages.copy()
```

**Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_history.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add ChatHistory class with basic message management"
```

---

### Task 2: Add summarization to ChatHistory

**Files:**
- Modify: `secator/tasks/ai_history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

```python
# Add to tests/unit/test_ai_history.py

class TestChatHistorySummarization(unittest.TestCase):

    def test_summarize_keeps_last_n_messages(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        # Add 6 messages (3 iterations worth)
        history.add_assistant("Iteration 1 response")
        history.add_tool("Iteration 1 results")
        history.add_assistant("Iteration 2 response")
        history.add_tool("Iteration 2 results")
        history.add_assistant("Iteration 3 response")
        history.add_tool("Iteration 3 results")

        # Mock summarizer that just returns "Summary"
        def mock_summarizer(messages):
            return "Summary of previous iterations"

        history.summarize(summarizer=mock_summarizer, keep_last=4)

        messages = history.to_messages()
        # Should have: 1 summary + 4 kept messages = 5
        self.assertEqual(len(messages), 5)
        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("Summary", messages[0]["content"])

    def test_summarize_no_op_when_few_messages(self):
        from secator.tasks.ai_history import ChatHistory

        history = ChatHistory()
        history.add_assistant("Response 1")
        history.add_tool("Results 1")

        def mock_summarizer(messages):
            return "Should not be called"

        history.summarize(summarizer=mock_summarizer, keep_last=4)

        messages = history.to_messages()
        # Should be unchanged - only 2 messages, less than keep_last
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["role"], "assistant")
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_history.py::TestChatHistorySummarization -v`
Expected: FAIL with "AttributeError: 'ChatHistory' object has no attribute 'summarize'"

**Step 3: Write minimal implementation**

```python
# Add to secator/tasks/ai_history.py ChatHistory class

    def summarize(self, summarizer: callable, keep_last: int = 4) -> None:
        """Summarize older messages, keeping the last N messages verbatim.

        Args:
            summarizer: Callable that takes messages list and returns summary string
            keep_last: Number of recent messages to keep verbatim (default: 4 = 2 iterations)
        """
        if len(self.messages) <= keep_last:
            return  # Nothing to summarize

        # Split messages
        messages_to_summarize = self.messages[:-keep_last]
        messages_to_keep = self.messages[-keep_last:]

        # Generate summary
        summary_text = summarizer(messages_to_summarize)

        # Rebuild messages with summary first
        self.messages = [
            {"role": "system", "content": summary_text}
        ] + messages_to_keep
```

**Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_history.py::TestChatHistorySummarization -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add summarization to ChatHistory"
```

---

### Task 3: Add LLM-based summarizer function

**Files:**
- Modify: `secator/tasks/ai_history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

```python
# Add to tests/unit/test_ai_history.py

from unittest.mock import patch, MagicMock

class TestLLMSummarizer(unittest.TestCase):

    @patch('secator.tasks.ai_history.get_llm_response')
    def test_create_llm_summarizer_calls_llm(self, mock_llm):
        from secator.tasks.ai_history import create_llm_summarizer

        mock_llm.return_value = "Summary: Found 2 vulns"

        summarizer = create_llm_summarizer(model="gpt-4o-mini")
        messages = [
            {"role": "assistant", "content": "Running nmap"},
            {"role": "tool", "content": "Port 80 open"},
        ]

        result = summarizer(messages)

        self.assertEqual(result, "Summary: Found 2 vulns")
        mock_llm.assert_called_once()

    @patch('secator.tasks.ai_history.get_llm_response')
    def test_summarizer_formats_messages_for_prompt(self, mock_llm):
        from secator.tasks.ai_history import create_llm_summarizer

        mock_llm.return_value = "Summary"

        summarizer = create_llm_summarizer(model="gpt-4o-mini")
        messages = [
            {"role": "assistant", "content": "Action 1"},
            {"role": "tool", "content": "Result 1"},
        ]

        summarizer(messages)

        # Check prompt contains the messages
        call_args = mock_llm.call_args
        prompt = call_args.kwargs.get('prompt') or call_args[1].get('prompt') or call_args[0][0]
        self.assertIn("Action 1", prompt)
        self.assertIn("Result 1", prompt)
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_history.py::TestLLMSummarizer -v`
Expected: FAIL with "cannot import name 'create_llm_summarizer'"

**Step 3: Write minimal implementation**

```python
# Add to secator/tasks/ai_history.py

from typing import Callable

SUMMARIZATION_PROMPT = """Summarize the following attack session history concisely.
Focus on:
- Commands/tools executed
- Key findings (vulnerabilities, open ports, services)
- Errors or failures
- Current attack progress

Keep the summary under 500 words. Use markdown formatting.

## History to summarize:

{history}

## Summary:"""


def create_llm_summarizer(
    model: str,
    api_base: str = None,
    temperature: float = 0.3,
) -> Callable[[List[Dict[str, str]]], str]:
    """Create a summarizer function that uses an LLM.

    Args:
        model: LLM model name
        api_base: Optional API base URL
        temperature: LLM temperature (default: 0.3 for factual summaries)

    Returns:
        Callable that takes messages and returns summary string
    """
    from secator.tasks.ai import get_llm_response

    def summarizer(messages: List[Dict[str, str]]) -> str:
        # Format messages for prompt
        history_text = ""
        for msg in messages:
            role = msg["role"].upper()
            content = msg["content"]
            history_text += f"**{role}:**\n{content}\n\n"

        prompt = SUMMARIZATION_PROMPT.format(history=history_text)

        summary = get_llm_response(
            prompt=prompt,
            model=model,
            api_base=api_base,
            temperature=temperature,
        )

        return f"## Summary of previous iterations\n\n{summary}"

    return summarizer
```

**Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_history.py::TestLLMSummarizer -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add LLM-based summarizer for chat history"
```

---

### Task 4: Create PromptBuilder class

**Files:**
- Create: `secator/tasks/ai_prompt_builder.py`
- Test: `tests/unit/test_ai_prompt_builder.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_prompt_builder.py
import unittest

class TestPromptBuilder(unittest.TestCase):

    def test_build_system_prompt(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        system_prompt = builder.build_system_prompt()

        self.assertIn("penetration testing", system_prompt.lower())
        self.assertIn("action", system_prompt.lower())

    def test_build_user_prompt(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        user_prompt = builder.build_user_prompt(
            targets=["192.168.1.1", "example.com"],
            instructions="Focus on web vulnerabilities"
        )

        self.assertIn("192.168.1.1", user_prompt)
        self.assertIn("example.com", user_prompt)
        self.assertIn("Focus on web vulnerabilities", user_prompt)

    def test_build_loop_query(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        query = builder.build_loop_query(iteration=3, max_iterations=10)

        self.assertIn("3", query)
        self.assertIn("10", query)

    def test_build_full_prompt_structure(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder
        from secator.tasks.ai_history import ChatHistory

        builder = PromptBuilder()
        history = ChatHistory()
        history.add_assistant("Running scan")
        history.add_tool("Found port 80")

        prompt = builder.build_full_prompt(
            targets=["target.com"],
            instructions="Test web app",
            history=history,
            iteration=2,
            max_iterations=5
        )

        # Should have all 4 sections
        self.assertIn("system", prompt)
        self.assertIn("user", prompt)
        self.assertIn("history", prompt)
        self.assertIn("query", prompt)
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_prompt_builder.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai_prompt_builder.py
"""Prompt builder for AI attack mode."""
from dataclasses import dataclass
from typing import Dict, List, Optional

from secator.tasks.ai_history import ChatHistory


SYSTEM_PROMPT_TEMPLATE = """You are an autonomous penetration testing agent conducting authorized security testing.

## Available Actions

Respond with a JSON array of actions. Each action must have an "action" field.

### execute
Run a security tool or shell command.
{{"action": "execute", "type": "task|shell", "name": "tool_name", "targets": ["..."], "opts": {{}}, "reasoning": "why", "expected_outcome": "what you expect"}}

### query
Query workspace for existing findings.
{{"action": "query", "query": {{"_type": "vulnerability", ...}}, "result_key": "unique_key", "reasoning": "why"}}

### validate
Confirm a vulnerability with proof.
{{"action": "validate", "vulnerability": "name", "target": "url", "proof": "evidence", "severity": "critical|high|medium|low", "reproduction_steps": ["..."]}}

### complete
Mark testing complete.
{{"action": "complete", "summary": "findings summary"}}

### stop
Stop testing.
{{"action": "stop", "reason": "why stopping"}}

## Output Format
Always respond with a valid JSON array of actions.
"""

USER_PROMPT_TEMPLATE = """## Targets
{targets_list}

## Instructions
{instructions}
"""

LOOP_QUERY_TEMPLATE = """Iteration {iteration}/{max_iterations}. Based on the history above, decide your next actions.
Respond with a JSON array of actions."""


@dataclass
class PromptBuilder:
    """Builds structured prompts for AI attack mode."""

    disable_secator: bool = False

    def build_system_prompt(self) -> str:
        """Build the system prompt with role and action schemas."""
        from secator.tasks.ai import get_system_prompt
        return get_system_prompt("attack", disable_secator=self.disable_secator)

    def build_user_prompt(self, targets: List[str], instructions: str = "") -> str:
        """Build the user prompt with targets and instructions."""
        targets_list = "\n".join(f"- {t}" for t in targets)
        return USER_PROMPT_TEMPLATE.format(
            targets_list=targets_list,
            instructions=instructions or "Conduct thorough security testing."
        )

    def build_loop_query(self, iteration: int, max_iterations: int) -> str:
        """Build the current loop query."""
        return LOOP_QUERY_TEMPLATE.format(
            iteration=iteration,
            max_iterations=max_iterations
        )

    def build_full_prompt(
        self,
        targets: List[str],
        instructions: str,
        history: ChatHistory,
        iteration: int,
        max_iterations: int,
    ) -> Dict[str, any]:
        """Build the complete prompt structure.

        Returns:
            Dict with keys: system, user, history, query
        """
        return {
            "system": self.build_system_prompt(),
            "user": self.build_user_prompt(targets, instructions),
            "history": history.to_messages(),
            "query": self.build_loop_query(iteration, max_iterations),
        }
```

**Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_prompt_builder.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompt_builder.py tests/unit/test_ai_prompt_builder.py
git commit -m "feat(ai): add PromptBuilder class for structured prompts"
```

---

### Task 5: Add encryption methods to PromptBuilder

**Files:**
- Modify: `secator/tasks/ai_prompt_builder.py`
- Test: `tests/unit/test_ai_prompt_builder.py`

**Step 1: Write the failing test**

```python
# Add to tests/unit/test_ai_prompt_builder.py

class TestPromptBuilderEncryption(unittest.TestCase):

    def test_encrypt_prompt_encrypts_all_fields(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder
        from unittest.mock import MagicMock

        # Mock encryptor
        encryptor = MagicMock()
        encryptor.encrypt.side_effect = lambda x: f"ENCRYPTED({x})"

        builder = PromptBuilder()
        prompt = {
            "system": "System prompt",
            "user": "User prompt with target.com",
            "history": [{"role": "assistant", "content": "Found vuln"}],
            "query": "Iteration 1/10"
        }

        encrypted = builder.encrypt_prompt(prompt, encryptor)

        # All string fields should be encrypted
        self.assertIn("ENCRYPTED", encrypted["user"])
        self.assertIn("ENCRYPTED", encrypted["query"])
        # History content should be encrypted
        self.assertIn("ENCRYPTED", encrypted["history"][0]["content"])

    def test_encrypt_prompt_skips_system(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder
        from unittest.mock import MagicMock

        encryptor = MagicMock()
        encryptor.encrypt.side_effect = lambda x: f"ENCRYPTED({x})"

        builder = PromptBuilder()
        prompt = {
            "system": "System prompt - no sensitive data",
            "user": "Target: secret.com",
            "history": [],
            "query": "Query"
        }

        encrypted = builder.encrypt_prompt(prompt, encryptor)

        # System prompt should NOT be encrypted (no sensitive data)
        self.assertEqual(encrypted["system"], "System prompt - no sensitive data")
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_prompt_builder.py::TestPromptBuilderEncryption -v`
Expected: FAIL with "AttributeError: 'PromptBuilder' object has no attribute 'encrypt_prompt'"

**Step 3: Write minimal implementation**

```python
# Add to secator/tasks/ai_prompt_builder.py PromptBuilder class

    def encrypt_prompt(self, prompt: Dict, encryptor) -> Dict:
        """Encrypt sensitive fields in the prompt.

        Args:
            prompt: Full prompt dict with system, user, history, query
            encryptor: SensitiveDataEncryptor instance

        Returns:
            Encrypted prompt dict
        """
        encrypted = prompt.copy()

        # System prompt doesn't contain sensitive data - skip
        # User prompt has targets/instructions - encrypt
        encrypted["user"] = encryptor.encrypt(prompt["user"])

        # Query has iteration info - encrypt
        encrypted["query"] = encryptor.encrypt(prompt["query"])

        # History has all conversation - encrypt each message content
        encrypted["history"] = []
        for msg in prompt["history"]:
            encrypted["history"].append({
                "role": msg["role"],
                "content": encryptor.encrypt(msg["content"])
            })

        return encrypted
```

**Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_prompt_builder.py::TestPromptBuilderEncryption -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompt_builder.py tests/unit/test_ai_prompt_builder.py
git commit -m "feat(ai): add encryption to PromptBuilder"
```

---

### Task 6: Add --summary-model CLI option and update intent_model default

**Files:**
- Modify: `secator/tasks/ai.py` (around line 2200 in meta options)
- Modify: `secator/config.py` (around line 213)

**Step 1: Find and read current options**

Run: `grep -n "max_iterations\|prompt_iterations\|intent_model" secator/tasks/ai.py | head -20`

**Step 2: Add summary_model option**

Add after `prompt_iterations` option (around line 2207):

```python
        "summary_model": {
            "type": str,
            "default": "claude-haiku-4-5",
            "help": "Model for summarizing chat history (default: claude-haiku-4-5)",
        },
```

**Step 3: Update intent_model default in config.py**

In `secator/config.py`, change line 213:

```python
	intent_model: str = 'claude-haiku-4-5'  # fast model for intent analysis
```

**Step 4: Verify syntax**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py secator/config.py`
Expected: No output (success)

**Step 5: Commit**

```bash
git add secator/tasks/ai.py secator/config.py
git commit -m "feat(ai): add --summary-model CLI option, set haiku as default for intent/summary"
```

---

### Task 7: Add format_prompt_for_llm helper

**Files:**
- Modify: `secator/tasks/ai_prompt_builder.py`
- Test: `tests/unit/test_ai_prompt_builder.py`

**Step 1: Write the failing test**

```python
# Add to tests/unit/test_ai_prompt_builder.py

class TestFormatPromptForLLM(unittest.TestCase):

    def test_format_prompt_for_llm_combines_sections(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        prompt = {
            "system": "You are an agent.",
            "user": "## Targets\n- target.com",
            "history": [
                {"role": "assistant", "content": "Running scan"},
                {"role": "tool", "content": "Port 80 open"}
            ],
            "query": "Iteration 1/10."
        }

        formatted = builder.format_prompt_for_llm(prompt)

        # Should be a single string with all parts
        self.assertIsInstance(formatted, str)
        self.assertIn("You are an agent", formatted)
        self.assertIn("target.com", formatted)
        self.assertIn("Running scan", formatted)
        self.assertIn("Port 80 open", formatted)
        self.assertIn("Iteration 1/10", formatted)

    def test_format_prompt_for_llm_empty_history(self):
        from secator.tasks.ai_prompt_builder import PromptBuilder

        builder = PromptBuilder()
        prompt = {
            "system": "System",
            "user": "User",
            "history": [],
            "query": "Query"
        }

        formatted = builder.format_prompt_for_llm(prompt)

        # Should not have history section header when empty
        self.assertIn("System", formatted)
        self.assertIn("User", formatted)
        self.assertIn("Query", formatted)
```

**Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_prompt_builder.py::TestFormatPromptForLLM -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# Add to secator/tasks/ai_prompt_builder.py PromptBuilder class

    def format_prompt_for_llm(self, prompt: Dict) -> str:
        """Format the structured prompt into a single string for LLM.

        Args:
            prompt: Dict with system, user, history, query

        Returns:
            Formatted string prompt
        """
        parts = []

        # System prompt
        parts.append(prompt["system"])
        parts.append("")  # blank line

        # User prompt
        parts.append(prompt["user"])
        parts.append("")

        # History (if any)
        if prompt["history"]:
            parts.append("## Chat History")
            parts.append("")
            for msg in prompt["history"]:
                role = msg["role"].upper()
                content = msg["content"]
                parts.append(f"**{role}:**")
                parts.append(content)
                parts.append("")

        # Current query
        parts.append("## Current Task")
        parts.append(prompt["query"])

        return "\n".join(parts)
```

**Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_prompt_builder.py::TestFormatPromptForLLM -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompt_builder.py tests/unit/test_ai_prompt_builder.py
git commit -m "feat(ai): add format_prompt_for_llm to PromptBuilder"
```

---

### Task 8: Refactor _mode_attack to use ChatHistory

**Files:**
- Modify: `secator/tasks/ai.py` (lines ~2621-2900)

**Step 1: Add imports at top of file**

Add after existing imports (around line 22):

```python
from secator.tasks.ai_history import ChatHistory, create_llm_summarizer
from secator.tasks.ai_prompt_builder import PromptBuilder
```

**Step 2: Initialize ChatHistory in _mode_attack**

In `_mode_attack`, after `ctx = self._build_action_context(...)` (around line 2695), add:

```python
        # Initialize chat history for this attack session
        chat_history = ChatHistory()

        # Initialize prompt builder
        prompt_builder = PromptBuilder(disable_secator=disable_secator)

        # Get summary model (default to claude-haiku-4-5)
        summary_model = self.run_opts.get("summary_model", "claude-haiku-4-5")
```

**Step 3: Verify syntax**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): initialize ChatHistory and PromptBuilder in _mode_attack"
```

---

### Task 9: Add history tracking in attack loop

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Track assistant responses in history**

After receiving LLM response (around line 2770), add:

```python
                # Add assistant response to history
                chat_history.add_assistant(response)
```

**Step 2: Track tool results in history**

After batch results are processed (around line 2868), add:

```python
                # Add tool results to history
                if batch_results:
                    tool_content = self._format_batch_results(batch_results)
                    chat_history.add_tool(tool_content)
```

**Step 3: Verify syntax**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): track responses and results in ChatHistory"
```

---

### Task 10: Add summarization at checkpoints

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Add summarization in checkpoint block**

In the checkpoint handling code (around line 2725), after handling checkpoint result, add:

```python
                    # Summarize history at checkpoint
                    if len(chat_history.messages) > 4:
                        summarizer = create_llm_summarizer(
                            model=summary_model,
                            api_base=api_base,
                            temperature=0.3,
                        )
                        yield Info(message="Summarizing chat history...")
                        chat_history.summarize(summarizer=summarizer, keep_last=4)
```

**Step 2: Verify syntax**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): add history summarization at checkpoints"
```

---

### Task 11: Refactor prompt building to use PromptBuilder

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Replace initial prompt building**

Replace the initial prompt creation (around lines 2697-2706) with:

```python
        # Build initial prompt using PromptBuilder
        full_prompt = prompt_builder.build_full_prompt(
            targets=targets,
            instructions=custom_prompt,
            history=chat_history,
            iteration=1,
            max_iterations=max_iterations,
        )

        # Encrypt at the edge if sensitive mode
        if sensitive:
            full_prompt = prompt_builder.encrypt_prompt(full_prompt, encryptor)

        # Format for LLM
        prompt = prompt_builder.format_prompt_for_llm(full_prompt)
```

**Step 2: Verify syntax**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): use PromptBuilder for initial prompt"
```

---

### Task 12: Refactor iteration prompts to use PromptBuilder

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Create helper method for building iteration prompts**

Add method to `ai` class (around line 3800):

```python
    def _build_iteration_prompt(
        self,
        prompt_builder: 'PromptBuilder',
        chat_history: 'ChatHistory',
        targets: List[str],
        instructions: str,
        iteration: int,
        max_iterations: int,
        encryptor: 'SensitiveDataEncryptor',
        sensitive: bool,
    ) -> str:
        """Build prompt for an attack iteration.

        Args:
            prompt_builder: PromptBuilder instance
            chat_history: ChatHistory with conversation so far
            targets: List of targets
            instructions: User instructions
            iteration: Current iteration number
            max_iterations: Maximum iterations
            encryptor: Encryptor for sensitive data
            sensitive: Whether to encrypt

        Returns:
            Formatted prompt string ready for LLM
        """
        full_prompt = prompt_builder.build_full_prompt(
            targets=targets,
            instructions=instructions,
            history=chat_history,
            iteration=iteration,
            max_iterations=max_iterations,
        )

        if sensitive:
            full_prompt = prompt_builder.encrypt_prompt(full_prompt, encryptor)

        return prompt_builder.format_prompt_for_llm(full_prompt)
```

**Step 2: Update loop to use helper**

Replace prompt building in loop iterations with calls to `_build_iteration_prompt`.

**Step 3: Verify syntax**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): use PromptBuilder for iteration prompts"
```

---

### Task 13: Remove old scattered encryption

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Identify and remove duplicate encryption**

Search for encryption calls that are now handled by PromptBuilder:

```bash
grep -n "encryptor.encrypt" secator/tasks/ai.py
```

**Step 2: Remove redundant encryption in prompt building paths**

The following should be removed as they're now handled by `encrypt_prompt`:
- Encryption of `targets_str` (line ~2673)
- Encryption of `custom_prompt_suffix` (line ~2682)
- Encryption of `batch_results_text` (line ~2859)
- Encryption of `executed_cmds` in various paths

**Step 3: Verify tests still pass**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai_handlers.py tests/unit/test_ai_safety.py -v`
Expected: All tests pass

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): remove scattered encryption, use single edge gate"
```

---

### Task 14: Run full test suite and fix any regressions

**Files:**
- All modified files

**Step 1: Run all AI-related tests**

Run: `source .venv/bin/activate && python -m pytest tests/unit/test_ai*.py -v`
Expected: All tests pass

**Step 2: Run syntax check**

Run: `source .venv/bin/activate && python -m py_compile secator/tasks/ai.py secator/tasks/ai_history.py secator/tasks/ai_prompt_builder.py`
Expected: No output (success)

**Step 3: Fix any failures**

Address any test failures or syntax errors.

**Step 4: Final commit**

```bash
git add -A
git commit -m "test(ai): fix regressions from prompt refactor"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | ChatHistory basic messages | ai_history.py |
| 2 | ChatHistory summarization | ai_history.py |
| 3 | LLM summarizer function | ai_history.py |
| 4 | PromptBuilder class | ai_prompt_builder.py |
| 5 | PromptBuilder encryption | ai_prompt_builder.py |
| 6 | --summary-model CLI option | ai.py |
| 7 | format_prompt_for_llm | ai_prompt_builder.py |
| 8 | Initialize in _mode_attack | ai.py |
| 9 | Track history in loop | ai.py |
| 10 | Summarize at checkpoints | ai.py |
| 11 | Use PromptBuilder for initial | ai.py |
| 12 | Use PromptBuilder for iterations | ai.py |
| 13 | Remove scattered encryption | ai.py |
| 14 | Full test suite | all |
