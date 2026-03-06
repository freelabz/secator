# AI Context Management Design

**Date:** 2026-03-06
**Status:** Approved
**Scope:** P0 - Reduce cost explosion through accurate token counting, output reservation, and fair allocation

## Problem

The current AI implementation has three issues causing cost explosion:

1. **Inaccurate token estimation** - `len(content) // 4` can be off by 2-3x, triggering compaction too early or too late
2. **No output reservation** - No space reserved for LLM response, causing truncation or errors
3. **Large tool outputs** - Single action results (nuclei, feroxbuster) consume most of the context

## Solution: Approach A (Minimal Changes to ChatHistory)

Localized changes to `history.py` and `ai.py` with ~100-150 lines modified.

---

## Section 1: Token Counting & Caching

**Location:** `secator/ai/history.py`

### Changes

1. **New instance variable** on ChatHistory:
   ```python
   model: Optional[str] = None
   ```

2. **New method `count_tokens()`** - Replaces `est_tokens()`:
   ```python
   def count_tokens(self, model: str = None) -> int:
       """Count tokens using litellm, with per-message caching."""
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

3. **Remove `est_tokens()`** - Delete entirely (flawed estimation)

4. **Invalidate cache on mode change** - Modify `set_system()`:
   ```python
   def set_system(self, content: str) -> None:
       for msg in self.messages:
           if msg["role"] == "system":
               msg["content"] = content
               msg.pop("_token_count", None)  # Invalidate cache
               msg.pop("_token_model", None)
               return
       self.messages.insert(0, {"role": "system", "content": content})
   ```

5. **Update callers in `ai.py`** - Replace `history.est_tokens()` with `history.count_tokens(model)`

---

## Section 2: Output Token Reservation

**Location:** `secator/ai/history.py`

### Changes

1. **New constants**:
   ```python
   OUTPUT_TOKEN_RESERVATION = 8192  # Reserve for LLM response
   COMPACTION_THRESHOLD_PCT = 85    # Trigger compaction at 85% of usable context
   ```

2. **New helper function**:
   ```python
   def get_context_window(model: str) -> int:
       """Get model's context window size from litellm."""
       try:
           info = litellm.get_model_info(model)
           return info.get("max_input_tokens") or info.get("max_tokens", 128_000)
       except Exception:
           return 128_000  # Safe default
   ```

3. **New method `should_compact()`**:
   ```python
   def should_compact(self, model: str, threshold_pct: int = COMPACTION_THRESHOLD_PCT) -> bool:
       """Check if compaction needed based on % of context used."""
       context_window = get_context_window(model)
       usable = context_window - OUTPUT_TOKEN_RESERVATION
       used = self.count_tokens(model)
       return used > (usable * threshold_pct / 100)
   ```

4. **Update `maybe_summarize()`** - Use percentage-based logic:
   ```python
   def maybe_summarize(self, model: str, ...) -> Tuple[bool, int, int]:
       old_tokens = self.count_tokens(model)
       if not self.should_compact(model):
           return False, old_tokens, old_tokens
       # ... rest of compaction logic
   ```

5. **Remove `threshold` parameter** from `maybe_summarize()` signature

6. **Update callers in `ai.py`** - Remove `threshold=max_tokens` argument

---

## Section 3: Fair Allocation for Action Results

**Location:** `secator/ai/history.py` + `secator/tasks/ai.py`

### Strategy

- Budget per action (sum of all results from that action)
- Cap at 10,000 tokens or 50% of available context (whichever is smaller)
- File fallback for truncated output:
  - **task/workflow**: Reference existing `reports_dir/report.json`
  - **shell**: Save to `reports_dir/.outputs/shell_<timestamp>.txt`

### Changes

1. **New method `get_action_budget()`** on ChatHistory:
   ```python
   def get_action_budget(self, model: str) -> int:
       """Get max tokens allowed for a single action's combined output."""
       available = self.get_available_tokens(model)
       MAX_ACTION_TOKENS = 10_000
       return min(MAX_ACTION_TOKENS, available // 2)

   def get_available_tokens(self, model: str) -> int:
       """Return tokens available for new content."""
       context_window = get_context_window(model)
       usable = context_window - OUTPUT_TOKEN_RESERVATION
       return usable - self.count_tokens(model)
   ```

2. **New helper function** for truncation:
   ```python
   def truncate_to_tokens(
       content: str,
       max_tokens: int,
       model: str,
       fallback_path: Path = None,  # Existing file (task/workflow)
       output_dir: Path = None,     # For shell commands only
       result_name: str = "result"
   ) -> str:
       """Truncate content to fit within token budget, with file fallback."""
       current = litellm.token_counter(model=model, text=content)
       if current <= max_tokens:
           return content

       # Determine file hint
       if fallback_path and fallback_path.exists():
           # Task/workflow: point to existing report.json
           file_hint = f"\nFull output: {fallback_path}"
       elif output_dir:
           # Shell: save to .outputs/
           output_dir.mkdir(parents=True, exist_ok=True)
           timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
           fallback_path = output_dir / f"{result_name}_{timestamp}.txt"
           fallback_path.write_text(content)
           file_hint = f"\nFull output saved to: {fallback_path}"
       else:
           file_hint = ""

       file_hint += "\nUse shell commands to explore: grep, head, tail, jq"

       # Truncate content
       ratio = max_tokens / current
       truncate_at = int(len(content) * ratio * 0.9)
       return content[:truncate_at] + f"\n\n[TRUNCATED]{file_hint}"
   ```

3. **Update action execution loop in `ai.py`**:
   ```python
   # After collecting action_results:
   budget = history.get_action_budget(model)
   tool_result = format_tool_result(name, status, count, action_results)

   # Determine fallback path
   if action_type in ("task", "workflow") and hasattr(runner, 'reports_dir'):
       fallback_path = runner.reports_dir / "report.json"
       tool_result = truncate_to_tokens(tool_result, budget, model, fallback_path=fallback_path)
   elif action_type == "shell":
       tool_result = truncate_to_tokens(
           tool_result, budget, model,
           output_dir=self.reports_dir / ".outputs",
           result_name="shell"
       )
   else:
       tool_result = truncate_to_tokens(tool_result, budget, model)

   history.add_user(tool_result)
   ```

---

## Section 4: Integration in Main Loop

**Location:** `secator/tasks/ai.py`

### Changes

1. **Set model on ChatHistory**:
   ```python
   history = ChatHistory()
   history.model = model
   history.add_system(get_system_prompt(mode))
   ```

2. **Update compaction check** - Remove threshold parameter:
   ```python
   summarized, old_tokens, new_tokens = history.maybe_summarize(
       model, api_base=api_base, api_key=api_key)
   ```

3. **Remove `max_tokens` option** - No longer needed

4. **Update token display**:
   ```python
   token_str = format_token_count(history.count_tokens(model), icon='arrow_up')
   ```

---

## Flow Diagram: Truncated Feroxbuster Example

```
┌─────────────────────────────────────────────────────┐
│ Action: feroxbuster → 2,847 URLs (82,000 tokens)    │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│ Budget: min(10,000, available // 2) = 10,000        │
│ 82,000 > 10,000 → TRUNCATE                          │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│ Reference existing: reports_dir/report.json         │
│ Add to history with [TRUNCATED] + file path hint    │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│ LLM sees partial data + hint                        │
│ Uses shell action: grep -i critical report.json     │
│ Gets focused results within budget                  │
└─────────────────────────────────────────────────────┘
```

---

## Files Modified

| File | Changes |
|------|---------|
| `secator/ai/history.py` | Add `count_tokens()`, `should_compact()`, `get_action_budget()`, `get_available_tokens()`, `truncate_to_tokens()`. Remove `est_tokens()`. Update `set_system()`, `maybe_summarize()`. Add constants. |
| `secator/tasks/ai.py` | Set `history.model`. Remove `max_tokens` option. Apply `get_action_budget()` + `truncate_to_tokens()` before adding results. Update token display. |

---

## Success Criteria

1. No more `len // 4` estimation anywhere
2. Compaction triggers at 85% of (context_window - 8192)
3. No single action result exceeds 10k tokens in history
4. Large outputs reference existing report.json or saved file
5. LLM can use shell commands to explore full data when needed
