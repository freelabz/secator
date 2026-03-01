# AI Phase 2: New Action Types Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add query, output_type, and prompt action handlers to AI attack mode.

**Architecture:** Extend the Phase 1 handler dispatch pattern with three new handlers. Each handler follows the existing `_handle_*` signature taking `(action: Dict, ctx: ActionContext)` and yielding OutputTypes. QueryEngine integration for workspace queries, dynamic OutputType creation for structured findings, and Rich-based user prompting for interactive guidance.

**Tech Stack:** Python 3.9+, secator QueryEngine, Rich prompts, existing OutputType classes

---

### Task 1: Add workspace fields to ActionContext

**Files:**
- Modify: `secator/tasks/ai.py:1357-1375`
- Test: `tests/unit/test_ai_handlers.py` (create)

**Step 1: Write the failing test**

Create `tests/unit/test_ai_handlers.py`:

```python
# tests/unit/test_ai_handlers.py

import unittest
from dataclasses import fields


class TestActionContext(unittest.TestCase):

    def test_action_context_has_workspace_fields(self):
        from secator.tasks.ai import ActionContext

        field_names = [f.name for f in fields(ActionContext)]

        self.assertIn('workspace_id', field_names)
        self.assertIn('workspace_name', field_names)
        self.assertIn('drivers', field_names)

    def test_action_context_workspace_defaults(self):
        from secator.tasks.ai import ActionContext

        ctx = ActionContext(targets=['target.com'], model='gpt-4')

        self.assertIsNone(ctx.workspace_id)
        self.assertIsNone(ctx.workspace_name)
        self.assertEqual(ctx.drivers, [])


if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestActionContext -v`
Expected: FAIL with "AssertionError" (workspace_id not in field_names)

**Step 3: Write minimal implementation**

Edit `secator/tasks/ai.py` at line 1374, add after `in_ci: bool = False`:

```python
    workspace_id: str = None
    workspace_name: str = None
    drivers: list = field(default_factory=list)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestActionContext -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): add workspace fields to ActionContext for Phase 2"
```

---

### Task 2: Add OUTPUT_TYPE_MAP constant

**Files:**
- Modify: `secator/tasks/ai.py:1391` (after ACTION_HANDLERS)
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestOutputTypeMap(unittest.TestCase):

    def test_output_type_map_exists(self):
        from secator.tasks.ai import OUTPUT_TYPE_MAP

        self.assertIsInstance(OUTPUT_TYPE_MAP, dict)

    def test_output_type_map_has_vulnerability(self):
        from secator.tasks.ai import OUTPUT_TYPE_MAP

        self.assertIn('vulnerability', OUTPUT_TYPE_MAP)
        self.assertEqual(OUTPUT_TYPE_MAP['vulnerability'], 'Vulnerability')

    def test_output_type_map_has_all_finding_types(self):
        from secator.tasks.ai import OUTPUT_TYPE_MAP

        expected = ['vulnerability', 'port', 'url', 'subdomain', 'ip', 'exploit', 'tag']
        for t in expected:
            self.assertIn(t, OUTPUT_TYPE_MAP)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestOutputTypeMap -v`
Expected: FAIL with "cannot import name 'OUTPUT_TYPE_MAP'"

**Step 3: Write minimal implementation**

Add after ACTION_HANDLERS (around line 1391) in `secator/tasks/ai.py`:

```python
# =============================================================================
# OUTPUT TYPE MAPPING
# =============================================================================

OUTPUT_TYPE_MAP = {
    "vulnerability": "Vulnerability",
    "exploit": "Exploit",
    "port": "Port",
    "url": "Url",
    "subdomain": "Subdomain",
    "ip": "Ip",
    "domain": "Domain",
    "tag": "Tag",
    "record": "Record",
    "certificate": "Certificate",
    "user_account": "UserAccount",
}
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestOutputTypeMap -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): add OUTPUT_TYPE_MAP constant for output_type action"
```

---

### Task 3: Update ACTION_HANDLERS registry

**Files:**
- Modify: `secator/tasks/ai.py:1381-1391`
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestActionHandlers(unittest.TestCase):

    def test_action_handlers_has_query(self):
        from secator.tasks.ai import ACTION_HANDLERS

        self.assertIn('query', ACTION_HANDLERS)
        self.assertEqual(ACTION_HANDLERS['query'], '_handle_query')

    def test_action_handlers_has_output_type(self):
        from secator.tasks.ai import ACTION_HANDLERS

        self.assertIn('output_type', ACTION_HANDLERS)
        self.assertEqual(ACTION_HANDLERS['output_type'], '_handle_output_type')

    def test_action_handlers_has_prompt(self):
        from secator.tasks.ai import ACTION_HANDLERS

        self.assertIn('prompt', ACTION_HANDLERS)
        self.assertEqual(ACTION_HANDLERS['prompt'], '_handle_prompt')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestActionHandlers -v`
Expected: FAIL with "AssertionError" (query not in ACTION_HANDLERS)

**Step 3: Write minimal implementation**

Edit `secator/tasks/ai.py` ACTION_HANDLERS (around line 1381-1391), replace the commented placeholders:

```python
ACTION_HANDLERS = {
    "execute": "_handle_execute",
    "validate": "_handle_validate",
    "complete": "_handle_complete",
    "stop": "_handle_stop",
    "report": "_handle_report",
    # Phase 2:
    "query": "_handle_query",
    "output_type": "_handle_output_type",
    "prompt": "_handle_prompt",
}
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestActionHandlers -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): register Phase 2 action handlers in ACTION_HANDLERS"
```

---

### Task 4: Implement _handle_query method

**Files:**
- Modify: `secator/tasks/ai.py` (add method to AI class, after `_handle_stop`)
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
from unittest.mock import Mock, patch


class TestHandleQuery(unittest.TestCase):

    def test_handle_query_no_workspace(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            workspace_id=None,
        )
        action = {'action': 'query', 'query': {'_type': 'vulnerability'}}

        results = list(ai._handle_query(action, ctx))

        # Should yield Warning about missing workspace
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'warning')
        self.assertIn('workspace', results[0].message.lower())

    @patch('secator.tasks.ai.QueryEngine')
    def test_handle_query_success(self, mock_engine_class):
        from secator.tasks.ai import AI, ActionContext

        # Setup mock
        mock_engine = Mock()
        mock_engine.search.return_value = [
            {'_type': 'vulnerability', 'name': 'SQLi'},
            {'_type': 'vulnerability', 'name': 'XSS'},
        ]
        mock_engine_class.return_value = mock_engine

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            workspace_id='ws123',
            workspace_name='test_ws',
            attack_context={},
        )
        action = {
            'action': 'query',
            'query': {'_type': 'vulnerability'},
            'result_key': 'vulns',
        }

        results = list(ai._handle_query(action, ctx))

        # Should yield Info with result count
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'info')
        self.assertIn('2', results[0].message)

        # Should store in attack_context
        self.assertIn('vulns', ctx.attack_context)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestHandleQuery -v`
Expected: FAIL with "AttributeError: 'AI' object has no attribute '_handle_query'"

**Step 3: Write minimal implementation**

Add method to AI class in `secator/tasks/ai.py` after `_handle_stop` (around line 3040):

```python
    def _handle_query(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle query action - fetch workspace results.

        Args:
            action: Query action with MongoDB-style query
            ctx: ActionContext with workspace info

        Yields:
            Info or Warning/Error outputs
        """
        query = action.get("query", {})
        result_key = action.get("result_key", "query_results")

        # Check workspace context
        if not ctx.workspace_id:
            yield Warning(message="Query action requires workspace context (-ws flag)")
            return

        # Execute query
        try:
            from secator.query import QueryEngine
            engine = QueryEngine(ctx.workspace_id, {
                'workspace_name': ctx.workspace_name,
                'drivers': ctx.drivers,
            })
            results = engine.search(query, limit=100)

            # Format results for context
            formatted = self._format_query_results(results)
            ctx.attack_context[result_key] = formatted

            yield Info(message=f"Query returned {len(results)} results (stored in {result_key})")

        except Exception as e:
            yield Error(message=f"Query failed: {e}")

    def _format_query_results(self, results: List[Dict]) -> str:
        """Format query results as string for LLM context.

        Args:
            results: List of result dictionaries

        Returns:
            Formatted string representation
        """
        if not results:
            return "No results found."

        lines = [f"Found {len(results)} results:"]
        for i, r in enumerate(results[:20], 1):  # Limit to 20 for context
            rtype = r.get('_type', 'unknown')
            if rtype == 'vulnerability':
                lines.append(f"  {i}. [{r.get('severity', '?')}] {r.get('name', '?')} @ {r.get('matched_at', '?')}")
            elif rtype == 'port':
                lines.append(f"  {i}. {r.get('ip', '?')}:{r.get('port', '?')} ({r.get('service_name', '?')})")
            elif rtype == 'url':
                lines.append(f"  {i}. {r.get('url', '?')} [{r.get('status_code', '?')}]")
            else:
                lines.append(f"  {i}. [{rtype}] {str(r)[:80]}")

        if len(results) > 20:
            lines.append(f"  ... and {len(results) - 20} more")

        return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestHandleQuery -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): implement _handle_query for workspace queries"
```

---

### Task 5: Implement _handle_output_type method

**Files:**
- Modify: `secator/tasks/ai.py` (add method to AI class)
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestHandleOutputType(unittest.TestCase):

    def test_handle_output_type_unknown_type(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'output_type',
            'output_type': 'invalid_type',
            'fields': {},
        }

        results = list(ai._handle_output_type(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'warning')
        self.assertIn('Unknown', results[0].message)

    def test_handle_output_type_vulnerability(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'output_type',
            'output_type': 'vulnerability',
            'fields': {
                'name': 'SQL Injection',
                'severity': 'high',
                'matched_at': 'https://target.com/login',
            },
        }

        results = list(ai._handle_output_type(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'vulnerability')
        self.assertEqual(results[0].name, 'SQL Injection')
        self.assertEqual(results[0].severity, 'high')

    def test_handle_output_type_port(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(targets=['target.com'], model='gpt-4')
        action = {
            'action': 'output_type',
            'output_type': 'port',
            'fields': {
                'port': 443,
                'ip': '192.168.1.1',
                'service_name': 'https',
            },
        }

        results = list(ai._handle_output_type(action, ctx))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]._type, 'port')
        self.assertEqual(results[0].port, 443)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestHandleOutputType -v`
Expected: FAIL with "AttributeError: 'AI' object has no attribute '_handle_output_type'"

**Step 3: Write minimal implementation**

Add method to AI class after `_handle_query`:

```python
    def _handle_output_type(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle output_type action - convert output to structured type.

        Args:
            action: Action with output_type and fields
            ctx: ActionContext (unused but required for interface)

        Yields:
            OutputType instance or Warning/Error
        """
        output_type = action.get("output_type", "").lower()
        fields_data = action.get("fields", {})

        # Validate output type
        if output_type not in OUTPUT_TYPE_MAP:
            valid_types = list(OUTPUT_TYPE_MAP.keys())
            yield Warning(message=f"Unknown output_type: {output_type}. Valid: {valid_types}")
            return

        # Import and create instance
        try:
            class_name = OUTPUT_TYPE_MAP[output_type]

            # Import from secator.output_types
            from secator import output_types
            OutputClass = getattr(output_types, class_name)

            # Add source metadata
            fields_data['_source'] = 'ai'

            instance = OutputClass(**fields_data)
            yield instance

        except TypeError as e:
            yield Error(message=f"Invalid fields for {output_type}: {e}")
        except Exception as e:
            yield Error(message=f"Failed to create {output_type}: {e}")
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestHandleOutputType -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): implement _handle_output_type for structured findings"
```

---

### Task 6: Implement _handle_prompt method

**Files:**
- Modify: `secator/tasks/ai.py` (add method to AI class)
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestHandlePrompt(unittest.TestCase):

    def test_handle_prompt_ci_mode_auto_select(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )
        action = {
            'action': 'prompt',
            'question': 'How to proceed?',
            'options': ['Option A', 'Option B'],
            'default': 'Option A',
        }

        results = list(ai._handle_prompt(action, ctx))

        # Should yield AI prompt and Info about auto-selection
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]._type, 'ai')
        self.assertEqual(results[1]._type, 'info')
        self.assertIn('Auto-selecting', results[1].message)
        self.assertEqual(ctx.attack_context['user_response'], 'Option A')

    def test_handle_prompt_auto_yes_mode(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            auto_yes=True,
            attack_context={},
        )
        action = {
            'action': 'prompt',
            'question': 'How to proceed?',
            'options': ['First', 'Second'],
            'default': 'Second',
        }

        results = list(ai._handle_prompt(action, ctx))

        self.assertEqual(ctx.attack_context['user_response'], 'Second')

    def test_handle_prompt_uses_first_option_when_no_default(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )
        action = {
            'action': 'prompt',
            'question': 'Choose one',
            'options': ['Alpha', 'Beta'],
        }

        results = list(ai._handle_prompt(action, ctx))

        # Should use first option as default
        self.assertEqual(ctx.attack_context['user_response'], 'Alpha')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestHandlePrompt -v`
Expected: FAIL with "AttributeError: 'AI' object has no attribute '_handle_prompt'"

**Step 3: Write minimal implementation**

Add method to AI class after `_handle_output_type`:

```python
    def _handle_prompt(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle prompt action - ask user for direction.

        Args:
            action: Prompt action with question and options
            ctx: ActionContext with mode flags

        Yields:
            AI prompt output and Info/Warning about selection
        """
        question = action.get("question", "")
        options = action.get("options", [])
        default = action.get("default", options[0] if options else "")

        # Display the question
        yield AI(
            content=question,
            ai_type="prompt",
            mode="attack",
            extra_data={"options": options, "default": default},
        )

        # Check if interactive mode
        if ctx.in_ci or ctx.auto_yes:
            yield Info(message=f"Auto-selecting: {default} (non-interactive mode)")
            ctx.attack_context["user_response"] = default
            return

        # Interactive prompt
        try:
            from rich.prompt import Prompt

            # Build choices display
            choices_display = " / ".join(f"[{i+1}] {opt}" for i, opt in enumerate(options))

            response = Prompt.ask(
                f"[bold cyan]Choose[/] ({choices_display})",
                choices=[str(i+1) for i in range(len(options))] + options,
                default="1",
            )

            # Convert number to option if needed
            if response.isdigit() and 1 <= int(response) <= len(options):
                selected = options[int(response) - 1]
            else:
                selected = response

            ctx.attack_context["user_response"] = selected
            yield Info(message=f"User selected: {selected}")

        except Exception as e:
            yield Warning(message=f"Prompt failed: {e}, using default: {default}")
            ctx.attack_context["user_response"] = default
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestHandlePrompt -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): implement _handle_prompt for user interaction"
```

---

### Task 7: Add system prompt documentation for new actions

**Files:**
- Modify: `secator/tasks/ai.py` (update PROMPT_ATTACK around line 405)
- No test needed (documentation change)

**Step 1: Locate the action documentation in PROMPT_ATTACK**

Read around line 405-476 to find the "Available Actions" section.

**Step 2: Add documentation for new actions**

Find the section after "### stop" in PROMPT_ATTACK and add:

```python
### query
Query workspace for existing findings. Requires -ws flag.
{{
  "action": "query",
  "query": {{"_type": "vulnerability", "severity": {{"$in": ["critical", "high"]}}}},
  "result_key": "critical_vulns",
  "reasoning": "why you need this data"
}}

Query operators: $in, $regex, $contains, $gt, $gte, $lt, $lte, $ne

### output_type
Convert findings to structured Secator output types.
{{
  "action": "output_type",
  "output_type": "vulnerability|port|url|subdomain|ip|exploit|tag",
  "fields": {{
    "name": "required for most types",
    "severity": "critical|high|medium|low|info",
    "matched_at": "where it was found"
  }},
  "reasoning": "why creating this output"
}}

### prompt
Ask user for direction (auto-selects default in CI/auto mode).
{{
  "action": "prompt",
  "question": "What should I do?",
  "options": ["Option A", "Option B", "Option C"],
  "default": "Option A",
  "reasoning": "why user input needed"
}}
```

**Step 3: Update allowed_actions in MODE_CONFIG**

Edit MODE_CONFIG around line 1408-1412 to include new actions:

```python
    "attack": {
        "iterative": True,
        "system_prompt_key": "attack",
        "allowed_actions": ["execute", "validate", "complete", "stop", "report", "query", "output_type", "prompt"],
    },
```

**Step 4: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 5: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "docs(ai): add Phase 2 action documentation to system prompt"
```

---

### Task 8: Run full test suite and verify

**Files:**
- Test: `tests/unit/test_ai_handlers.py`
- Test: `tests/unit/test_ai_safety.py`

**Step 1: Run all new handler tests**

Run: `python -m pytest tests/unit/test_ai_handlers.py -v`
Expected: All tests PASS

**Step 2: Run existing AI tests to ensure no regressions**

Run: `python -m pytest tests/unit/test_ai_safety.py -v`
Expected: All tests PASS

**Step 3: Verify syntax of entire file**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Final commit if any fixes needed**

If any fixes were made:
```bash
git add -A
git commit -m "fix(ai): address test issues from Phase 2 implementation"
```

---

## Summary

| Task | Description | Files Modified |
|------|-------------|----------------|
| 1 | Add workspace fields to ActionContext | ai.py, test_ai_handlers.py |
| 2 | Add OUTPUT_TYPE_MAP constant | ai.py, test_ai_handlers.py |
| 3 | Update ACTION_HANDLERS registry | ai.py, test_ai_handlers.py |
| 4 | Implement _handle_query method | ai.py, test_ai_handlers.py |
| 5 | Implement _handle_output_type method | ai.py, test_ai_handlers.py |
| 6 | Implement _handle_prompt method | ai.py, test_ai_handlers.py |
| 7 | Add system prompt documentation | ai.py |
| 8 | Run full test suite | - |

**Total estimated lines added:** ~230
**Total commits:** 8
