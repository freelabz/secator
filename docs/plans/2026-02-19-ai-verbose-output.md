# AI Task Verbose Output Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace raw LiteLLM debug logs with structured Secator Info outputs when --verbose is enabled.

**Architecture:** Add a `_truncate()` helper function, then add `yield Info()` statements in each mode handler around LLM calls and command execution. Uses existing `--verbose` flag.

**Tech Stack:** Python, Secator output_types (Info)

---

### Task 1: Add _truncate Helper Function

**Files:**
- Modify: `secator/tasks/ai.py:145` (after `load_sensitive_patterns` function)

**Step 1: Add the _truncate function**

Add after `load_sensitive_patterns()` function (around line 145):

```python
def _truncate(text: str, max_length: int = 2000) -> str:
    """Truncate text to max_length, adding indicator if truncated."""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length] + '\n... (truncated)'
```

**Step 2: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add _truncate helper for verbose output"
```

---

### Task 2: Add Verbose Output to _mode_summarize

**Files:**
- Modify: `secator/tasks/ai.py` - `_mode_summarize()` method

**Step 1: Add verbose flag and prompt output**

At the start of `_mode_summarize()`, after building the prompt and before `get_llm_response()`:

```python
        verbose = self.run_opts.get('verbose', False)
```

Then before the `try:` block with `get_llm_response()`:

```python
        if verbose:
            yield Info(message=f"[PROMPT] {_truncate(prompt)}")
```

**Step 2: Add agent response output**

After `response = get_llm_response(...)` and after decryption, before yielding the Tag:

```python
            if verbose:
                yield Info(message=f"[AGENT] {_truncate(response)}")
```

**Step 3: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add verbose output to summarize mode"
```

---

### Task 3: Add Verbose Output to _mode_suggest

**Files:**
- Modify: `secator/tasks/ai.py` - `_mode_suggest()` method

**Step 1: Add verbose flag and prompt output**

At the start of `_mode_suggest()`, after `in_ci = _is_ci()`:

```python
        verbose = self.run_opts.get('verbose', False)
```

Then before the `try:` block:

```python
        if verbose:
            yield Info(message=f"[PROMPT] {_truncate(prompt)}")
```

**Step 2: Add agent response output**

After `response = get_llm_response(...)` and after decryption:

```python
            if verbose:
                yield Info(message=f"[AGENT] {_truncate(response)}")
```

**Step 3: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add verbose output to suggest mode"
```

---

### Task 4: Add Verbose Output to _mode_attack (LLM calls)

**Files:**
- Modify: `secator/tasks/ai.py` - `_mode_attack()` method

**Step 1: Add verbose flag**

Near the start of `_mode_attack()`, after `dry_run = self.run_opts.get('dry_run', False)`:

```python
        verbose = self.run_opts.get('verbose', False)
```

**Step 2: Add prompt output before LLM call**

Inside the `for iteration` loop, before `response = get_llm_response(...)`:

```python
                if verbose:
                    yield Info(message=f"[PROMPT] {_truncate(prompt)}")
```

**Step 3: Add agent response output**

After `response = get_llm_response(...)` and after decryption:

```python
                if verbose:
                    yield Info(message=f"[AGENT] {_truncate(response)}")
```

**Step 4: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 5: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add verbose LLM output to attack mode"
```

---

### Task 5: Add Verbose Output to _mode_attack (Command Execution)

**Files:**
- Modify: `secator/tasks/ai.py` - `_mode_attack()` method, execute action block

**Step 1: Replace existing Info with verbose CMD output**

Find this line (around line 794):
```python
                    yield Info(message=f"Executing: {command}")
```

Replace with:
```python
                    if verbose:
                        yield Info(message=f"[CMD] {command}")
```

**Step 2: Add OUTPUT after command execution**

After `result_output = self._execute_command(command)` (and after the dry_run block), add:

```python
                    if verbose:
                        yield Info(message=f"[OUTPUT] {_truncate(result_output)}")
```

**Step 3: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add verbose command output to attack mode"
```

---

### Task 6: Manual Test

**Step 1: Test summarize mode with verbose**

Run: `secator x ai example.com --mode summarize --verbose --model gpt-4o-mini`
Expected: See `[PROMPT]` and `[AGENT]` outputs in terminal

**Step 2: Test attack mode with verbose (dry run)**

Run: `secator x ai testphp.vulnweb.com --mode attack --verbose --dry-run --model gpt-4o-mini`
Expected: See `[PROMPT]`, `[AGENT]`, `[CMD]` outputs in terminal

**Step 3: Final commit (if any fixes needed)**

```bash
git add secator/tasks/ai.py
git commit -m "fix(ai): verbose output adjustments"
```
