# AI Checkpoint & Continuation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add periodic user checkpoints during attack execution and end-of-loop continuation prompting.

**Architecture:** Add `--prompt-iterations` CLI option with default `min(max_iterations // 2, 5)`. Insert checkpoint logic at start of each iteration in `_mode_attack`. Add continuation loop after attack loop ends. Reuse existing `_handle_prompt` infrastructure. Skip all prompts in CI/auto_yes mode.

**Tech Stack:** Python 3.9+, Rich prompts, existing `_handle_prompt` method

---

### Task 1: Add prompt_iterations CLI option

**Files:**
- Modify: `secator/tasks/ai.py:2172-2176`
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestPromptIterations(unittest.TestCase):

    def test_prompt_iterations_option_exists(self):
        from secator.tasks.ai import ai

        self.assertIn('prompt_iterations', ai.opts)

    def test_prompt_iterations_default_is_none(self):
        from secator.tasks.ai import ai

        self.assertIsNone(ai.opts['prompt_iterations']['default'])
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestPromptIterations -v`
Expected: FAIL with "AssertionError" (prompt_iterations not in opts)

**Step 3: Write minimal implementation**

Edit `secator/tasks/ai.py` after `max_iterations` option (around line 2176), add:

```python
        "prompt_iterations": {
            "type": int,
            "default": None,
            "help": "Prompt user for direction every N iterations (default: min(max_iterations/2, 5))",
        },
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestPromptIterations -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): add prompt_iterations CLI option"
```

---

### Task 2: Add _prompt_checkpoint method

**Files:**
- Modify: `secator/tasks/ai.py` (add method to AI class after `_handle_prompt`)
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestPromptCheckpoint(unittest.TestCase):

    def test_prompt_checkpoint_returns_continue(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )

        # In CI mode, should auto-select and return "continue"
        results = list(ai._prompt_checkpoint(5, 10, ctx))

        # Should yield AI prompt and Info
        self.assertEqual(len(results), 2)
        self.assertEqual(ctx.attack_context.get('_checkpoint_result'), 'continue')

    def test_prompt_checkpoint_stop_response(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={'user_response': 'Stop and summarize'},
        )

        # Simulate stop selection
        ctx.attack_context['user_response'] = 'Stop and summarize'
        result = ai._parse_checkpoint_response(ctx)

        self.assertEqual(result, 'stop')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestPromptCheckpoint -v`
Expected: FAIL with "AttributeError: 'AI' object has no attribute '_prompt_checkpoint'"

**Step 3: Write minimal implementation**

Add methods to AI class after `_handle_prompt` (around line 3220):

```python
    def _prompt_checkpoint(self, iteration: int, max_iterations: int, ctx: 'ActionContext') -> Generator:
        """Prompt user at periodic checkpoint.

        Args:
            iteration: Current iteration number (1-indexed)
            max_iterations: Total max iterations
            ctx: ActionContext with mode flags

        Yields:
            AI and Info outputs from _handle_prompt
        """
        checkpoint_action = {
            "action": "prompt",
            "question": f"Checkpoint at iteration {iteration}/{max_iterations}. How should I proceed?",
            "options": [
                "Continue attacking",
                "Change direction",
                "Stop and summarize"
            ],
            "default": "Continue attacking",
        }

        yield from self._handle_prompt(checkpoint_action, ctx)

        # Parse response and store result
        result = self._parse_checkpoint_response(ctx)
        ctx.attack_context['_checkpoint_result'] = result

    def _parse_checkpoint_response(self, ctx: 'ActionContext') -> str:
        """Parse checkpoint response into action.

        Returns:
            'continue', 'stop', or 'change'
        """
        user_response = ctx.attack_context.get("user_response", "Continue attacking")

        if "Stop" in user_response:
            return "stop"
        elif "Change" in user_response:
            return "change"
        else:
            return "continue"
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestPromptCheckpoint -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): add _prompt_checkpoint method for periodic user prompts"
```

---

### Task 3: Add _prompt_continuation method

**Files:**
- Modify: `secator/tasks/ai.py` (add method after `_prompt_checkpoint`)
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestPromptContinuation(unittest.TestCase):

    def test_prompt_continuation_ci_mode_returns_stop(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )

        results = list(ai._prompt_continuation(ctx))

        # In CI mode, default is "Stop and generate report"
        self.assertEqual(len(results), 2)
        self.assertEqual(ctx.attack_context.get('_continuation_result'), 'stop')

    def test_prompt_continuation_continue_response(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={'user_response': 'Continue with more iterations'},
        )

        result = ai._parse_continuation_response(ctx)

        self.assertEqual(result, 'continue')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestPromptContinuation -v`
Expected: FAIL with "AttributeError: 'AI' object has no attribute '_prompt_continuation'"

**Step 3: Write minimal implementation**

Add methods after `_parse_checkpoint_response`:

```python
    def _prompt_continuation(self, ctx: 'ActionContext') -> Generator:
        """Prompt user for continuation after loop ends.

        Args:
            ctx: ActionContext with mode flags

        Yields:
            AI and Info outputs from _handle_prompt
        """
        continuation_action = {
            "action": "prompt",
            "question": "Attack loop completed. What would you like to do?",
            "options": [
                "Continue with more iterations",
                "Provide new instructions",
                "Stop and generate report"
            ],
            "default": "Stop and generate report",
        }

        yield from self._handle_prompt(continuation_action, ctx)

        # Parse response and store result
        result = self._parse_continuation_response(ctx)
        ctx.attack_context['_continuation_result'] = result

    def _parse_continuation_response(self, ctx: 'ActionContext') -> str:
        """Parse continuation response into action.

        Returns:
            'continue', 'stop', or 'change'
        """
        user_response = ctx.attack_context.get("user_response", "Stop")

        if "Stop" in user_response:
            return "stop"
        elif "Continue" in user_response:
            return "continue"
        else:
            return "change"
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestPromptContinuation -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): add _prompt_continuation method for end-of-loop prompts"
```

---

### Task 4: Add _get_new_instructions helper

**Files:**
- Modify: `secator/tasks/ai.py`
- Test: `tests/unit/test_ai_handlers.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_handlers.py`:

```python
class TestGetNewInstructions(unittest.TestCase):

    def test_get_new_instructions_ci_mode_returns_empty(self):
        from secator.tasks.ai import AI, ActionContext

        ai = AI.__new__(AI)
        ctx = ActionContext(
            targets=['target.com'],
            model='gpt-4',
            in_ci=True,
            attack_context={},
        )

        result = ai._get_new_instructions(ctx)

        # In CI mode, can't get user input, return empty
        self.assertEqual(result, "")
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestGetNewInstructions -v`
Expected: FAIL with "AttributeError"

**Step 3: Write minimal implementation**

Add method after `_parse_continuation_response`:

```python
    def _get_new_instructions(self, ctx: 'ActionContext') -> str:
        """Get new instructions from user.

        Args:
            ctx: ActionContext with mode flags

        Returns:
            User's new instructions or empty string in CI mode
        """
        if ctx.in_ci or ctx.auto_yes:
            return ""

        try:
            from rich.prompt import Prompt
            return Prompt.ask("[bold cyan]New instructions[/]")
        except Exception:
            return ""
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_handlers.py::TestGetNewInstructions -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_handlers.py
git commit -m "feat(ai): add _get_new_instructions helper"
```

---

### Task 5: Integrate checkpoint into attack loop

**Files:**
- Modify: `secator/tasks/ai.py:2677-2680` (attack loop start)
- No new tests (integration)

**Step 1: Read current attack loop**

Read `secator/tasks/ai.py` around line 2595-2680 to understand the current loop structure.

**Step 2: Add prompt_iterations calculation**

After `max_iterations = int(self.run_opts.get("max_iterations", 10))` (around line 2601), add:

```python
        # Calculate prompt_iterations default
        prompt_iterations = self.run_opts.get("prompt_iterations")
        if prompt_iterations is None:
            prompt_iterations = min(max_iterations // 2, 5)
        else:
            prompt_iterations = int(prompt_iterations)
```

**Step 3: Add checkpoint logic at start of loop**

Inside the `for iteration in range(max_iterations):` loop, after `attack_context["iteration"] = iteration + 1`, add:

```python
            # Periodic checkpoint (skip first iteration, skip in CI/auto_yes)
            if iteration > 0 and prompt_iterations > 0 and iteration % prompt_iterations == 0:
                if not ctx.in_ci and not ctx.auto_yes:
                    yield from self._prompt_checkpoint(iteration + 1, max_iterations, ctx)

                    checkpoint_result = ctx.attack_context.get('_checkpoint_result', 'continue')

                    if checkpoint_result == 'stop':
                        yield Info(message="User requested stop at checkpoint")
                        break
                    elif checkpoint_result == 'change':
                        new_instructions = self._get_new_instructions(ctx)
                        if new_instructions:
                            custom_prompt_suffix = new_instructions
                            yield Info(message=f"New instructions: {new_instructions}")
```

**Step 4: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 5: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): integrate periodic checkpoints into attack loop"
```

---

### Task 6: Add end-of-loop continuation

**Files:**
- Modify: `secator/tasks/ai.py:2847-2863` (after attack loop)
- No new tests (integration)

**Step 1: Refactor end-of-loop logic**

Replace the current end-of-loop summary logic (lines 2847-2863) with continuation loop:

```python
        # End-of-loop continuation
        should_generate_summary = True

        while not ctx.in_ci and not ctx.auto_yes:
            yield from self._prompt_continuation(ctx)

            continuation_result = ctx.attack_context.get('_continuation_result', 'stop')

            if continuation_result == 'stop':
                break
            elif continuation_result == 'continue':
                # Run another batch of iterations
                yield Info(message=f"Continuing for {prompt_iterations} more iterations...")
                for extra_iteration in range(prompt_iterations):
                    ctx.attack_context["iteration"] += 1
                    yield Info(message=f"Extra iteration {extra_iteration + 1}/{prompt_iterations}")

                    # Run one iteration of the attack loop
                    # (simplified - reuse existing iteration logic)
                    try:
                        response = get_llm_response(
                            prompt=prompt,
                            model=model,
                            system_prompt=get_system_prompt("attack", disable_secator=disable_secator),
                            temperature=temperature,
                            api_base=api_base,
                        )
                        if sensitive:
                            response = encryptor.decrypt(response)

                        actions = self._parse_attack_actions(response)
                        if actions:
                            for action in actions:
                                action_type = action.get("action", "")
                                if action_type in ("complete", "stop"):
                                    should_generate_summary = True
                                    break
                                for result in self._dispatch_action(action, ctx):
                                    yield result
                    except Exception as e:
                        yield Warning(message=f"Continuation iteration failed: {e}")

            elif continuation_result == 'change':
                new_instructions = self._get_new_instructions(ctx)
                if new_instructions:
                    custom_prompt_suffix = new_instructions
                    prompt = self._build_continuation_prompt(ctx, new_instructions, encryptor, sensitive)
                    yield Info(message=f"New instructions applied: {new_instructions}")
                    # Continue the while loop to run with new instructions
                    continue
            else:
                break

        # Generate final summary
        if should_generate_summary:
            yield Info(message="Generating comprehensive attack summary...")
            full_summary = generate_attack_summary_with_llm(
                ctx.attack_context,
                model=ctx.model,
                api_base=ctx.api_base,
                temperature=ctx.temperature,
            )
            yield AI(
                content=full_summary,
                ai_type='attack_summary',
                mode='attack',
                model=ctx.model,
            )
```

**Step 2: Add _build_continuation_prompt helper**

Add after `_get_new_instructions`:

```python
    def _build_continuation_prompt(
        self, ctx: 'ActionContext', new_instructions: str,
        encryptor: 'SensitiveDataEncryptor', sensitive: bool
    ) -> str:
        """Build prompt for continuation with new instructions.

        Args:
            ctx: ActionContext with attack context
            new_instructions: User's new instructions
            encryptor: Encryptor for sensitive data
            sensitive: Whether to encrypt

        Returns:
            Formatted prompt string
        """
        executed_cmds = format_executed_commands(ctx.attack_context)
        if sensitive and executed_cmds:
            executed_cmds = encryptor.encrypt(executed_cmds)

        targets_str = ", ".join(ctx.targets)
        if sensitive:
            targets_str = encryptor.encrypt(targets_str)

        return PROMPT_ATTACK_CONTINUE.format(
            reason="received new instructions from user",
            executed_commands=executed_cmds,
            targets=targets_str,
            user_instructions=new_instructions
        )
```

**Step 3: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add end-of-loop continuation prompting"
```

---

### Task 7: Run full test suite

**Files:**
- Test: `tests/unit/test_ai_handlers.py`
- Test: `tests/unit/test_ai_safety.py`

**Step 1: Run all handler tests**

Run: `python -m pytest tests/unit/test_ai_handlers.py -v`
Expected: All tests PASS

**Step 2: Run safety tests for regressions**

Run: `python -m pytest tests/unit/test_ai_safety.py -v`
Expected: All tests PASS

**Step 3: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Final commit if needed**

```bash
git add -A
git commit -m "fix(ai): address any test issues from checkpoint implementation"
```

---

## Summary

| Task | Description | Lines Added |
|------|-------------|-------------|
| 1 | Add prompt_iterations CLI option | ~5 |
| 2 | Add _prompt_checkpoint method | ~35 |
| 3 | Add _prompt_continuation method | ~35 |
| 4 | Add _get_new_instructions helper | ~15 |
| 5 | Integrate checkpoint into attack loop | ~20 |
| 6 | Add end-of-loop continuation | ~60 |
| 7 | Run full test suite | - |

**Total estimated lines added:** ~170
**Total commits:** 7
