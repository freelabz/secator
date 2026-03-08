# "All of the above" Option Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an "All of the above" option to the AI follow-up menu that combines all LLM-suggested choices into a single message.

**Architecture:** Modify `prompt_user()` in `secator/ai/utils.py` to insert an "All of the above" option after LLM choices when 2+ choices exist. Add a new `all_choices` action handler that formats all choices into a numbered list message.

**Tech Stack:** Python, unittest

---

## Task 1: Add tests for "All of the above" functionality

**Files:**
- Modify: `tests/unit/test_ai_utils.py`

**Step 1: Write the failing tests**

Add a new test class at the end of `tests/unit/test_ai_utils.py` (before the `if __name__` block):

```python
class TestPromptUserAllChoices(unittest.TestCase):
    """Tests for the 'All of the above' option in prompt_user."""

    @patch('secator.ai.utils.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_not_shown_with_single_choice(self, mock_menu_class):
        """All of the above should not appear with only 1 choice."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        mock_menu = MagicMock()
        mock_menu.show.return_value = (0, "")  # Select first option
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        prompt_user(history, choices=["Single choice"])

        # Check options passed to InteractiveMenu
        call_args = mock_menu_class.call_args
        options = call_args[0][1]  # Second positional arg is options list
        labels = [opt["label"] for opt in options]

        self.assertNotIn("All of the above", labels)

    @patch('secator.ai.utils.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_shown_with_multiple_choices(self, mock_menu_class):
        """All of the above should appear with 2+ choices."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        mock_menu = MagicMock()
        mock_menu.show.return_value = (0, "")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        prompt_user(history, choices=["Choice A", "Choice B"])

        call_args = mock_menu_class.call_args
        options = call_args[0][1]
        labels = [opt["label"] for opt in options]

        self.assertIn("All of the above", labels)

    @patch('secator.ai.utils.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_position_after_llm_choices(self, mock_menu_class):
        """All of the above should appear after LLM choices, before defaults."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        mock_menu = MagicMock()
        mock_menu.show.return_value = (0, "")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        prompt_user(history, choices=["Choice A", "Choice B", "Choice C"])

        call_args = mock_menu_class.call_args
        options = call_args[0][1]
        labels = [opt["label"] for opt in options]

        # Expected order: Choice A, Choice B, Choice C, All of the above, Continue, Summarize, Exit
        all_idx = labels.index("All of the above")
        self.assertEqual(all_idx, 3)  # After 3 LLM choices

    @patch('secator.ai.utils.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_formats_message_correctly(self, mock_menu_class):
        """Selecting All of the above should format all choices into numbered list."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        choices = ["Scan for ports", "Enumerate subdomains"]

        mock_menu = MagicMock()
        # Simulate selecting "All of the above" (index 2 with 2 choices)
        mock_menu.show.return_value = (2, "")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        result = prompt_user(history, choices=choices, max_iterations=10)

        # Check the message added to history
        last_msg = history.messages[-1]
        expected = "Do all of the following: 1) Scan for ports, 2) Enumerate subdomains"
        self.assertEqual(last_msg["content"], expected)
        self.assertEqual(result[0], expected)

    @patch('secator.ai.utils.InteractiveMenu')
    @patch('secator.definitions.IN_WORKER', False)
    def test_all_choices_with_extra_instructions(self, mock_menu_class):
        """Extra user input should be appended to the message."""
        from secator.ai.utils import prompt_user
        from secator.ai.history import ChatHistory

        choices = ["Choice A", "Choice B"]

        mock_menu = MagicMock()
        mock_menu.show.return_value = (2, "focus on main domain")
        mock_menu_class.return_value = mock_menu

        history = ChatHistory()
        history.add_system("system")

        result = prompt_user(history, choices=choices)

        last_msg = history.messages[-1]
        expected = "Do all of the following: 1) Choice A, 2) Choice B. Additional instructions: focus on main domain"
        self.assertEqual(last_msg["content"], expected)
```

**Step 2: Run tests to verify they fail**

Run: `secator test unit --test TestPromptUserAllChoices`

Expected: FAIL - tests should fail because `all_choices` action doesn't exist yet

**Step 3: Commit test file**

```bash
git add tests/unit/test_ai_utils.py
git commit -m "test: add tests for 'All of the above' option in AI follow-up menu"
```

---

## Task 2: Implement "All of the above" option

**Files:**
- Modify: `secator/ai/utils.py:385-442`

**Step 1: Add "All of the above" option after LLM choices**

In `prompt_user()`, after the loop that inserts LLM choices (around line 396), add:

```python
# Insert LLM-provided choices first
if choices:
    for choice in choices:
        options.append({
            "label": choice,
            "description": "",
            "input": True,
            "action": "follow_up",
        })

    # Add "All of the above" when 2+ choices
    if len(choices) >= 2:
        options.append({
            "label": "All of the above",
            "description": "Run all suggested actions",
            "input": True,
            "action": "all_choices",
        })
```

**Step 2: Add handler for `all_choices` action**

After the `follow_up` action handler (around line 442), add:

```python
if action == "all_choices":
    numbered = [f"{i}) {c}" for i, c in enumerate(choices, 1)]
    msg = f"Do all of the following: {', '.join(numbered)}"
    if value:
        msg += f". Additional instructions: {value}"
    history.add_user(_maybe_encrypt(msg, encryptor))
    return (msg, max_iterations)
```

**Step 3: Run tests to verify they pass**

Run: `secator test unit --test TestPromptUserAllChoices`

Expected: PASS - all 5 tests should pass

**Step 4: Run full test suite to check for regressions**

Run: `secator test unit --test test_ai_utils`

Expected: PASS - all existing tests should still pass

**Step 5: Commit implementation**

```bash
git add secator/ai/utils.py
git commit -m "feat(ai): add 'All of the above' option to follow-up menu

When the LLM suggests 2+ follow-up choices, adds an 'All of the above'
option that combines all choices into a single message for the LLM to
handle in one turn."
```

---

## Task 3: Manual verification

**Step 1: Run AI task with a prompt that generates multiple choices**

Run: `secator x ai --prompt "What reconnaissance should I do on example.com?" --mode attack`

Expected: When the LLM returns follow-up choices, "All of the above" should appear after the LLM choices.

**Step 2: Select "All of the above" and verify message**

Expected: The message sent to LLM should be formatted as:
"Do all of the following: 1) [Choice 1], 2) [Choice 2], ..."

**Step 3: Verify LLM responds with multiple actions**

Expected: The LLM should respond with actions addressing all the choices.

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Add failing tests | `tests/unit/test_ai_utils.py` |
| 2 | Implement feature | `secator/ai/utils.py` |
| 3 | Manual verification | N/A |
