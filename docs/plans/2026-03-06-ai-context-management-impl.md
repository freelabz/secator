# AI Context Management Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce AI task cost explosion through accurate token counting, output reservation, and fair allocation per action.

**Architecture:** Minimal changes to `ChatHistory` class in `history.py` plus integration updates in `ai.py`. Replace flawed `len//4` estimation with `litellm.token_counter()`, add percentage-based compaction thresholds, and truncate large action outputs with file fallback.

**Tech Stack:** Python, litellm, existing secator test infrastructure

---

## Task 1: Add Accurate Token Counting with Caching

**Files:**
- Modify: `secator/ai/history.py:104-106` (replace `est_tokens`)
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test for count_tokens**

Add to `tests/unit/test_ai_history.py`:

```python
@patch('secator.ai.history.litellm')
def test_count_tokens_uses_litellm(self, mock_litellm):
    """count_tokens uses litellm.token_counter for accurate counting."""
    mock_litellm.token_counter.return_value = 42

    history = ChatHistory()
    history.add_user("test message")

    tokens = history.count_tokens("gpt-4")

    mock_litellm.token_counter.assert_called_once()
    self.assertEqual(tokens, 42)

@patch('secator.ai.history.litellm')
def test_count_tokens_caches_result(self, mock_litellm):
    """count_tokens caches result and reuses on second call."""
    mock_litellm.token_counter.return_value = 100

    history = ChatHistory()
    history.add_user("test message")

    # First call - should hit litellm
    tokens1 = history.count_tokens("gpt-4")
    # Second call - should use cache
    tokens2 = history.count_tokens("gpt-4")

    # litellm called only once due to caching
    self.assertEqual(mock_litellm.token_counter.call_count, 1)
    self.assertEqual(tokens1, 100)
    self.assertEqual(tokens2, 100)

@patch('secator.ai.history.litellm')
def test_count_tokens_invalidates_cache_on_model_change(self, mock_litellm):
    """count_tokens recounts when model changes."""
    mock_litellm.token_counter.side_effect = [100, 120]

    history = ChatHistory()
    history.add_user("test message")

    tokens1 = history.count_tokens("gpt-4")
    tokens2 = history.count_tokens("claude-3")  # Different model

    self.assertEqual(mock_litellm.token_counter.call_count, 2)
    self.assertEqual(tokens1, 100)
    self.assertEqual(tokens2, 120)

def test_count_tokens_requires_model(self):
    """count_tokens raises ValueError when no model provided."""
    history = ChatHistory()
    history.add_user("test")

    with self.assertRaises(ValueError) as ctx:
        history.count_tokens()
    self.assertIn("Model required", str(ctx.exception))
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test test_count_tokens`
Expected: FAIL with "ChatHistory has no attribute 'count_tokens'"

**Step 3: Implement count_tokens in history.py**

Add import at top of `secator/ai/history.py`:

```python
import litellm
```

Add instance variable to ChatHistory dataclass (line ~37):

```python
model: Optional[str] = None
```

Replace `est_tokens` method (lines 104-106) with:

```python
def count_tokens(self, model: str = None) -> int:
    """Count tokens using litellm, with per-message caching.

    Args:
        model: LLM model name (required if self.model not set)

    Returns:
        Total token count across all messages

    Raises:
        ValueError: If no model provided and self.model not set
    """
    model = model or self.model
    if not model:
        raise ValueError("Model required for token counting")
    total = 0
    for msg in self.messages:
        cached = msg.get("_token_count")
        cached_model = msg.get("_token_model")
        if cached is not None and cached_model == model:
            total += cached
        else:
            tokens = litellm.token_counter(model=model, messages=[msg])
            msg["_token_count"] = tokens
            msg["_token_model"] = model
            total += tokens
    return total
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test test_count_tokens`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add accurate token counting with caching

Replace est_tokens with count_tokens using litellm.token_counter.
Caches token count per message, invalidates on model change.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Invalidate Cache on System Prompt Change

**Files:**
- Modify: `secator/ai/history.py:42-48` (update `set_system`)
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_history.py`:

```python
@patch('secator.ai.history.litellm')
def test_set_system_invalidates_token_cache(self, mock_litellm):
    """set_system invalidates cached token count for system message."""
    mock_litellm.token_counter.return_value = 50

    history = ChatHistory()
    history.add_system("old prompt")

    # Count tokens - this caches the count
    history.count_tokens("gpt-4")
    self.assertEqual(mock_litellm.token_counter.call_count, 1)

    # Change system prompt
    history.set_system("new longer prompt")

    # Count again - should recount since cache invalidated
    history.count_tokens("gpt-4")
    self.assertEqual(mock_litellm.token_counter.call_count, 2)
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test test_set_system_invalidates`
Expected: FAIL - call_count will be 1 (cache not invalidated)

**Step 3: Update set_system to invalidate cache**

Modify `set_system` method in `secator/ai/history.py` (lines 42-48):

```python
def set_system(self, content: str) -> None:
    """Replace the first system message, or insert one at the start.

    Invalidates any cached token count for the system message.
    """
    for msg in self.messages:
        if msg["role"] == "system":
            msg["content"] = content
            msg.pop("_token_count", None)  # Invalidate cache
            msg.pop("_token_model", None)
            return
    self.messages.insert(0, {"role": "system", "content": content})
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test test_set_system_invalidates`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): invalidate token cache on system prompt change

Ensures mode switches (attack <-> chat) trigger token recount.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Add Context Window Helper and Constants

**Files:**
- Modify: `secator/ai/history.py` (add constants and helper)
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_history.py`:

```python
@patch('secator.ai.history.litellm')
def test_get_context_window_returns_model_limit(self, mock_litellm):
    """get_context_window returns model's max input tokens."""
    from secator.ai.history import get_context_window

    mock_litellm.get_model_info.return_value = {"max_input_tokens": 128000}

    result = get_context_window("gpt-4")

    mock_litellm.get_model_info.assert_called_once_with("gpt-4")
    self.assertEqual(result, 128000)

@patch('secator.ai.history.litellm')
def test_get_context_window_fallback_on_error(self, mock_litellm):
    """get_context_window returns default on error."""
    from secator.ai.history import get_context_window

    mock_litellm.get_model_info.side_effect = Exception("API error")

    result = get_context_window("unknown-model")

    self.assertEqual(result, 128000)  # Default fallback

def test_constants_defined(self):
    """Verify constants are defined."""
    from secator.ai.history import OUTPUT_TOKEN_RESERVATION, COMPACTION_THRESHOLD_PCT

    self.assertEqual(OUTPUT_TOKEN_RESERVATION, 8192)
    self.assertEqual(COMPACTION_THRESHOLD_PCT, 85)
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test "test_get_context_window or test_constants_defined"`
Expected: FAIL with "cannot import name 'get_context_window'"

**Step 3: Add constants and helper function**

Add at top of `secator/ai/history.py` (after imports, before SUMMARIZATION_PROMPT):

```python
OUTPUT_TOKEN_RESERVATION = 8192  # Reserve for LLM response
COMPACTION_THRESHOLD_PCT = 85    # Trigger compaction at 85% of usable context


def get_context_window(model: str) -> int:
    """Get model's context window size from litellm.

    Args:
        model: LLM model name

    Returns:
        Context window size in tokens (default 128000 on error)
    """
    try:
        info = litellm.get_model_info(model)
        return info.get("max_input_tokens") or info.get("max_tokens", 128_000)
    except Exception:
        return 128_000  # Safe default
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test "test_get_context_window or test_constants_defined"`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add context window helper and token reservation constants

OUTPUT_TOKEN_RESERVATION=8192, COMPACTION_THRESHOLD_PCT=85
get_context_window() fetches model limits from litellm.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Add should_compact and get_available_tokens Methods

**Files:**
- Modify: `secator/ai/history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing tests**

Add to `tests/unit/test_ai_history.py`:

```python
@patch('secator.ai.history.get_context_window')
@patch('secator.ai.history.litellm')
def test_get_available_tokens(self, mock_litellm, mock_get_ctx):
    """get_available_tokens returns usable - used tokens."""
    mock_get_ctx.return_value = 128000
    mock_litellm.token_counter.return_value = 1000

    history = ChatHistory()
    history.add_user("test")

    available = history.get_available_tokens("gpt-4")

    # 128000 - 8192 (reservation) - 1000 (used) = 118808
    self.assertEqual(available, 118808)

@patch('secator.ai.history.get_context_window')
@patch('secator.ai.history.litellm')
def test_should_compact_below_threshold(self, mock_litellm, mock_get_ctx):
    """should_compact returns False when under threshold."""
    mock_get_ctx.return_value = 100000
    mock_litellm.token_counter.return_value = 1000  # 1% used

    history = ChatHistory()
    history.add_user("test")

    self.assertFalse(history.should_compact("gpt-4"))

@patch('secator.ai.history.get_context_window')
@patch('secator.ai.history.litellm')
def test_should_compact_above_threshold(self, mock_litellm, mock_get_ctx):
    """should_compact returns True when over threshold."""
    mock_get_ctx.return_value = 100000
    # Usable = 100000 - 8192 = 91808
    # 85% of 91808 = 78037
    mock_litellm.token_counter.return_value = 80000  # Over 85%

    history = ChatHistory()
    history.add_user("test")

    self.assertTrue(history.should_compact("gpt-4"))
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test "test_get_available_tokens or test_should_compact"`
Expected: FAIL with "has no attribute 'get_available_tokens'"

**Step 3: Add methods to ChatHistory**

Add to ChatHistory class in `secator/ai/history.py`:

```python
def get_available_tokens(self, model: str) -> int:
    """Return tokens available for new content.

    Args:
        model: LLM model name

    Returns:
        Available tokens (context - reservation - used)
    """
    context_window = get_context_window(model)
    usable = context_window - OUTPUT_TOKEN_RESERVATION
    return usable - self.count_tokens(model)

def should_compact(self, model: str, threshold_pct: int = COMPACTION_THRESHOLD_PCT) -> bool:
    """Check if compaction needed based on % of context used.

    Args:
        model: LLM model name
        threshold_pct: Percentage threshold (default 85)

    Returns:
        True if compaction needed
    """
    context_window = get_context_window(model)
    usable = context_window - OUTPUT_TOKEN_RESERVATION
    used = self.count_tokens(model)
    return used > (usable * threshold_pct / 100)
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test "test_get_available_tokens or test_should_compact"`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add should_compact and get_available_tokens methods

Percentage-based compaction threshold (85% of usable context).
Usable context = context_window - OUTPUT_TOKEN_RESERVATION.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Add get_action_budget Method

**Files:**
- Modify: `secator/ai/history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_history.py`:

```python
@patch('secator.ai.history.get_context_window')
@patch('secator.ai.history.litellm')
def test_get_action_budget_caps_at_max(self, mock_litellm, mock_get_ctx):
    """get_action_budget caps at MAX_ACTION_TOKENS when plenty available."""
    mock_get_ctx.return_value = 200000
    mock_litellm.token_counter.return_value = 1000  # Very little used

    history = ChatHistory()
    history.add_user("test")

    budget = history.get_action_budget("gpt-4")

    # Should cap at 10000 even though much more is available
    self.assertEqual(budget, 10000)

@patch('secator.ai.history.get_context_window')
@patch('secator.ai.history.litellm')
def test_get_action_budget_uses_half_available(self, mock_litellm, mock_get_ctx):
    """get_action_budget uses 50% of available when constrained."""
    mock_get_ctx.return_value = 50000
    # Usable = 50000 - 8192 = 41808
    # Used = 35000
    # Available = 41808 - 35000 = 6808
    # Half = 3404
    mock_litellm.token_counter.return_value = 35000

    history = ChatHistory()
    history.add_user("test")

    budget = history.get_action_budget("gpt-4")

    # Should be 50% of available (3404), less than max (10000)
    self.assertEqual(budget, 3404)
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test test_get_action_budget`
Expected: FAIL with "has no attribute 'get_action_budget'"

**Step 3: Add get_action_budget method**

Add constant at top of `secator/ai/history.py` (with other constants):

```python
MAX_ACTION_TOKENS = 10_000  # Hard cap per action result
```

Add method to ChatHistory class:

```python
def get_action_budget(self, model: str) -> int:
    """Get max tokens allowed for a single action's combined output.

    Returns the smaller of:
    - MAX_ACTION_TOKENS (10k hard cap)
    - 50% of available context

    Args:
        model: LLM model name

    Returns:
        Token budget for action result
    """
    available = self.get_available_tokens(model)
    return min(MAX_ACTION_TOKENS, available // 2)
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test test_get_action_budget`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add get_action_budget for fair token allocation

Caps action results at min(10k, 50% available context).
Prevents single large output from starving subsequent actions.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Add truncate_to_tokens Helper Function

**Files:**
- Modify: `secator/ai/history.py`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing tests**

Add to `tests/unit/test_ai_history.py`:

```python
from pathlib import Path
import tempfile

@patch('secator.ai.history.litellm')
def test_truncate_to_tokens_no_truncation_needed(self, mock_litellm):
    """truncate_to_tokens returns content unchanged when under budget."""
    from secator.ai.history import truncate_to_tokens

    mock_litellm.token_counter.return_value = 100

    result = truncate_to_tokens("short content", 500, "gpt-4")

    self.assertEqual(result, "short content")

@patch('secator.ai.history.litellm')
def test_truncate_to_tokens_truncates_with_marker(self, mock_litellm):
    """truncate_to_tokens truncates and adds [TRUNCATED] marker."""
    from secator.ai.history import truncate_to_tokens

    mock_litellm.token_counter.return_value = 1000
    content = "x" * 4000  # Long content

    result = truncate_to_tokens(content, 100, "gpt-4")

    self.assertIn("[TRUNCATED]", result)
    self.assertLess(len(result), len(content))

@patch('secator.ai.history.litellm')
def test_truncate_to_tokens_with_fallback_path(self, mock_litellm):
    """truncate_to_tokens includes existing file path in hint."""
    from secator.ai.history import truncate_to_tokens

    mock_litellm.token_counter.return_value = 1000

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"test": true}')
        fallback_path = Path(f.name)

    try:
        result = truncate_to_tokens("x" * 4000, 100, "gpt-4", fallback_path=fallback_path)

        self.assertIn("[TRUNCATED]", result)
        self.assertIn(str(fallback_path), result)
        self.assertIn("grep", result)  # Shell command hint
    finally:
        fallback_path.unlink()

@patch('secator.ai.history.litellm')
def test_truncate_to_tokens_saves_shell_output(self, mock_litellm):
    """truncate_to_tokens saves shell output to .outputs directory."""
    from secator.ai.history import truncate_to_tokens

    mock_litellm.token_counter.return_value = 1000
    content = "shell output " * 500

    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)

        result = truncate_to_tokens(
            content, 100, "gpt-4",
            output_dir=output_dir,
            result_name="shell"
        )

        self.assertIn("[TRUNCATED]", result)
        self.assertIn("saved to:", result)

        # Verify file was created
        saved_files = list(output_dir.glob("shell_*.txt"))
        self.assertEqual(len(saved_files), 1)
        self.assertEqual(saved_files[0].read_text(), content)
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test truncate_to_tokens`
Expected: FAIL with "cannot import name 'truncate_to_tokens'"

**Step 3: Implement truncate_to_tokens**

Add import at top of `secator/ai/history.py`:

```python
from datetime import datetime
from pathlib import Path
```

Add function after `get_context_window`:

```python
def truncate_to_tokens(
    content: str,
    max_tokens: int,
    model: str,
    fallback_path: Path = None,
    output_dir: Path = None,
    result_name: str = "result"
) -> str:
    """Truncate content to fit within token budget, with file fallback.

    Args:
        content: Content to truncate
        max_tokens: Maximum tokens allowed
        model: LLM model name for token counting
        fallback_path: Existing file to reference (task/workflow report.json)
        output_dir: Directory to save shell output (creates file)
        result_name: Prefix for saved filename

    Returns:
        Original content if under budget, or truncated with [TRUNCATED] marker
    """
    current = litellm.token_counter(model=model, text=content)
    if current <= max_tokens:
        return content

    # Determine file hint
    if fallback_path and fallback_path.exists():
        file_hint = f"\nFull output: {fallback_path}"
    elif output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fallback_path = output_dir / f"{result_name}_{timestamp}.txt"
        fallback_path.write_text(content)
        file_hint = f"\nFull output saved to: {fallback_path}"
    else:
        file_hint = ""

    file_hint += "\nUse shell commands to explore: grep, head, tail, jq"

    # Truncate content (ratio-based with 10% safety margin)
    ratio = max_tokens / current
    truncate_at = int(len(content) * ratio * 0.9)
    return content[:truncate_at] + f"\n\n[TRUNCATED]{file_hint}"
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test truncate_to_tokens`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "feat(ai): add truncate_to_tokens with file fallback

Truncates large outputs to token budget.
References existing report.json for task/workflow.
Saves shell output to .outputs/ directory.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Update maybe_summarize to Use New Token Counting

**Files:**
- Modify: `secator/ai/history.py:108-127`
- Test: `tests/unit/test_ai_history.py`

**Step 1: Write the failing test**

Update existing tests in `tests/unit/test_ai_history.py`:

```python
@patch('secator.ai.history.get_context_window')
@patch('secator.ai.utils.call_llm')
@patch('secator.ai.history.litellm')
def test_maybe_summarize_uses_percentage_threshold(self, mock_litellm, mock_call_llm, mock_get_ctx):
    """maybe_summarize uses percentage-based threshold, not fixed tokens."""
    mock_get_ctx.return_value = 100000
    # Usable = 100000 - 8192 = 91808
    # 85% threshold = 78037 tokens
    mock_litellm.token_counter.return_value = 80000  # Over 85%
    mock_call_llm.return_value = {"content": "Summary.", "usage": None}

    history = ChatHistory()
    history.add_system("system")
    history.add_user("user1")
    history.add_assistant("response1")

    summarized, old_tokens, new_tokens = history.maybe_summarize("gpt-4")

    self.assertTrue(summarized)
    mock_call_llm.assert_called_once()

@patch('secator.ai.history.get_context_window')
@patch('secator.ai.history.litellm')
def test_maybe_summarize_no_threshold_param(self, mock_litellm, mock_get_ctx):
    """maybe_summarize no longer accepts threshold parameter."""
    mock_get_ctx.return_value = 100000
    mock_litellm.token_counter.return_value = 1000

    history = ChatHistory()
    history.add_system("system")

    # Should work without threshold param
    summarized, _, _ = history.maybe_summarize("gpt-4")

    self.assertFalse(summarized)
```

**Step 2: Run test to verify it fails**

Run: `secator test unit --test test_maybe_summarize_uses_percentage`
Expected: FAIL (old implementation uses est_tokens and threshold param)

**Step 3: Update maybe_summarize signature and implementation**

Modify `maybe_summarize` in `secator/ai/history.py`:

```python
def maybe_summarize(self, model: str, api_base: Optional[str] = None,
                    api_key: Optional[str] = None) -> Tuple[bool, int, int]:
    """Summarize history if token usage exceeds percentage threshold.

    Uses should_compact() to determine if compaction is needed based on
    percentage of usable context (default 85%).

    Args:
        model: LLM model name
        api_base: Optional API base URL
        api_key: Optional API key

    Returns:
        tuple: (compacted, old_tokens, new_tokens)
    """
    old_tokens = self.count_tokens(model)
    if not self.should_compact(model):
        return False, old_tokens, old_tokens

    self._summarize_with_llm(model, api_base, api_key)
    new_tokens = self.count_tokens(model)
    return True, old_tokens, new_tokens
```

Also update `_summarize_with_llm` to remove threshold param and use count_tokens:

```python
def _summarize_with_llm(self, model: str, api_base: Optional[str] = None,
                        api_key: Optional[str] = None) -> None:
    """Summarize non-system messages using an LLM, keeping the initial system prompt intact."""
    if len(self.messages) <= 2:
        return

    # Preserve system prompt and first user message, summarize the rest
    system_msgs = [m for m in self.messages if m["role"] == "system"]
    non_system_msgs = [m for m in self.messages if m["role"] != "system"]
    initial_system = system_msgs[0] if system_msgs else None
    first_user = non_system_msgs[0] if non_system_msgs else None
    rest = non_system_msgs[1:] if len(non_system_msgs) > 1 else []

    if not rest:
        return

    from secator.ai.utils import call_llm
    from secator.rich import console
    from secator.utils import format_token_count

    # Calculate target summary size based on available context
    context_window = get_context_window(model)
    usable = context_window - OUTPUT_TOKEN_RESERVATION
    target_tokens = int(usable * 0.3)  # Target 30% of usable context
    max_words = target_tokens // 2  # Rough tokens-to-words ratio

    history_text = json.dumps(rest, indent=None)
    prompt = SUMMARIZATION_PROMPT.format(history=history_text, max_words=max_words)
    token_str = format_token_count(self.count_tokens(model), icon='arrow_up')
    with console.status(f"[bold orange3]Compacting chat history...[/] [gray42] • {token_str}[/]", spinner="dots"):
        result = call_llm([{"role": "user", "content": prompt}], model, 0.3, api_base, api_key)

    self.messages = []
    if initial_system:
        self.messages.append(initial_system)
    if first_user:
        self.messages.append(first_user)
    self.messages.append({"role": "user", "content": f"Summary of previous iterations:\n\n{result['content']}"})
```

**Step 4: Run test to verify it passes**

Run: `secator test unit --test test_maybe_summarize`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "refactor(ai): update maybe_summarize to use percentage threshold

Remove fixed threshold parameter.
Use should_compact() with 85% of usable context.
Use count_tokens() for accurate token counting.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Remove est_tokens and Update Tests

**Files:**
- Modify: `secator/ai/history.py` (delete est_tokens)
- Modify: `tests/unit/test_ai_history.py` (remove est_tokens tests)

**Step 1: Identify tests to remove**

Tests to delete from `tests/unit/test_ai_history.py`:
- `test_est_tokens_empty`
- `test_est_tokens`
- `test_est_tokens_multiple_messages`

**Step 2: Remove est_tokens method**

Delete from `secator/ai/history.py` lines 104-106:

```python
# DELETE THIS METHOD:
def est_tokens(self) -> int:
    """Estimate token count (1 token ~ 4 chars)."""
    return sum(len(m.get("content", "")) for m in self.messages) // 4
```

**Step 3: Remove est_tokens tests**

Delete from `tests/unit/test_ai_history.py`:

```python
# DELETE THESE TESTS:
def test_est_tokens_empty(self):
    ...

def test_est_tokens(self):
    ...

def test_est_tokens_multiple_messages(self):
    ...
```

**Step 4: Run all history tests to verify nothing breaks**

Run: `secator test unit --test test_ai_history`
Expected: PASS (no references to est_tokens remain)

**Step 5: Commit**

```bash
git add secator/ai/history.py tests/unit/test_ai_history.py
git commit -m "refactor(ai): remove flawed est_tokens method

All token counting now uses accurate litellm.token_counter.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Update ai.py to Use New Token Management

**Files:**
- Modify: `secator/tasks/ai.py`
- Test: Manual integration test

**Step 1: Update imports and set model on history**

In `secator/tasks/ai.py`, find line ~167 and update:

```python
# Before:
history = ChatHistory()
history.add_system(get_system_prompt(mode))

# After:
history = ChatHistory()
history.model = model  # Set model for token counting
history.add_system(get_system_prompt(mode))
```

**Step 2: Update compaction call (remove threshold param)**

Find line ~190-191 and update:

```python
# Before:
summarized, old_tokens, new_tokens = history.maybe_summarize(
    model, api_base=api_base, api_key=api_key, threshold=max_tokens)

# After:
summarized, old_tokens, new_tokens = history.maybe_summarize(
    model, api_base=api_base, api_key=api_key)
```

**Step 3: Update token display**

Find line ~200 and update:

```python
# Before:
token_str = format_token_count(history.est_tokens(), icon='arrow_up')

# After:
token_str = format_token_count(history.count_tokens(model), icon='arrow_up')
```

**Step 4: Remove max_tokens option references**

Remove from opts dict (line ~52):

```python
# DELETE THIS LINE:
"max_tokens": {"type": int, "default": CONFIG.addons.ai.max_tokens, "help": "Max tokens before compacting history"},
```

Remove the variable assignment (line ~159):

```python
# DELETE THIS LINE:
max_tokens = int(self.run_opts.get("max_tokens", CONFIG.addons.ai.max_tokens))
```

**Step 5: Run lint check**

Run: `secator test lint`
Expected: PASS (no flake8 errors)

**Step 6: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "refactor(ai): update ai.py to use new token management

- Set history.model for accurate counting
- Remove max_tokens option (use percentage threshold)
- Use count_tokens() instead of est_tokens()

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Integrate Fair Allocation in Action Loop

**Files:**
- Modify: `secator/tasks/ai.py`
- Modify: `secator/ai/actions.py` (add reports_dir to runner)

**Step 1: Import truncate_to_tokens**

Add to imports in `secator/tasks/ai.py`:

```python
from secator.ai.history import ChatHistory, truncate_to_tokens
```

**Step 2: Update action execution loop**

Find the action execution section (around lines 244-282) and update:

```python
for action in actions:
    action_type = action.get("action", "")
    is_secator = action_type in ['task', 'workflow']
    action_results = []
    has_errors = False
    runner = None  # Track runner for reports_dir

    for item in dispatch_action(action, ctx):
        if isinstance(item, (Stat, Progress, State, Info)):
            continue
        if isinstance(item, Error):
            has_errors = True
        if isinstance(item, Ai):
            self.add_result(item)
            if item.ai_type == "follow_up":
                follow_up_choices = (item.extra_data or {}).get("choices", [])
            if item.ai_type == "shell_output":
                action_results.append({"output": item.content})
            continue
        if isinstance(item, OutputType):
            self.add_result(item, print=not is_secator)
            item = item.toDict(exclude=list(INTERNAL_FIELDS))
        action_results.append(item)

        if ctx.scope == "current":
            ctx.results.append(item)

    # Build tool result with fair allocation
    tool_result = format_tool_result(
        action.get("name", action_type),
        "error" if has_errors else "success",
        len(action_results),
        action_results
    )

    # Apply token budget and truncation
    budget = history.get_action_budget(model)
    if action_type in ("task", "workflow"):
        # Reference existing report.json
        fallback_path = self.reports_dir / "report.json" if self.reports_dir else None
        tool_result = truncate_to_tokens(tool_result, budget, model, fallback_path=fallback_path)
    elif action_type == "shell":
        # Save shell output to .outputs/
        output_dir = self.reports_dir / ".outputs" if self.reports_dir else None
        tool_result = truncate_to_tokens(
            tool_result, budget, model,
            output_dir=output_dir,
            result_name="shell"
        )
    else:
        tool_result = truncate_to_tokens(tool_result, budget, model)

    tool_result = _maybe_encrypt(tool_result, encryptor)
    history.add_user(tool_result)
```

**Step 3: Run lint check**

Run: `secator test lint`
Expected: PASS

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): integrate fair allocation in action loop

Apply get_action_budget() and truncate_to_tokens() to all action results.
- task/workflow: reference existing report.json
- shell: save to .outputs/ directory
- others: truncate without file fallback

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 11: Final Integration Test

**Step 1: Run all AI unit tests**

Run: `secator test unit --test test_ai`
Expected: All tests PASS

**Step 2: Run lint**

Run: `secator test lint`
Expected: PASS

**Step 3: Manual smoke test**

Run a simple AI task to verify everything works:

```bash
secator x ai example.com -p "List the target"
```

Expected: Task runs without errors, token counting works

**Step 4: Final commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix(ai): address integration test issues

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Add count_tokens with caching | history.py, test_ai_history.py |
| 2 | Invalidate cache on set_system | history.py, test_ai_history.py |
| 3 | Add constants and get_context_window | history.py, test_ai_history.py |
| 4 | Add should_compact and get_available_tokens | history.py, test_ai_history.py |
| 5 | Add get_action_budget | history.py, test_ai_history.py |
| 6 | Add truncate_to_tokens | history.py, test_ai_history.py |
| 7 | Update maybe_summarize | history.py, test_ai_history.py |
| 8 | Remove est_tokens | history.py, test_ai_history.py |
| 9 | Update ai.py token management | ai.py |
| 10 | Integrate fair allocation | ai.py |
| 11 | Final integration test | - |
