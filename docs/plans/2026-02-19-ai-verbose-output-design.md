# AI Task Verbose Output Design

## Overview

Replace raw LiteLLM debug logs with structured Secator `Info` outputs when `--verbose` is enabled. This provides cleaner, more readable debugging output that integrates with Secator's output system.

## Current Problem

When `--verbose` is set, LiteLLM emits raw debug logs like:
```
POST Request Sent from LiteLLM:
curl -X POST https://api.anthropic.com/v1/messages ...
```

These logs are verbose, unstructured, and don't integrate with Secator's output formatting.

## Design

### Output Format

When `--verbose` is enabled, yield structured Info outputs with descriptive tags:

```
[INF] [PROMPT] Analyze the following penetration test results...
## Current Findings
...truncated after 2000 chars...

[INF] [AGENT] Looking at the current findings, I have successfully demonstrated...
...truncated after 2000 chars...

[INF] [CMD] curl -s 'http://example.com/hpp/?pp=12' -L

[INF] [OUTPUT] <title>HTTP Parameter Pollution Example</title>
...truncated after 2000 chars...
```

### Tags

- `[PROMPT]` - The user prompt being sent to the LLM (not system prompt)
- `[AGENT]` - The LLM's response
- `[CMD]` - Command about to be executed (attack mode)
- `[OUTPUT]` - Command execution result (attack mode)

### Truncation

Add a simple head truncation helper:

```python
def _truncate(text: str, max_length: int = 2000) -> str:
    """Truncate text to max_length, adding indicator if truncated."""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length] + '\n... (truncated)'
```

This differs from existing `trim_string()` which truncates from the middle. Head truncation is more appropriate for prompts/responses where the beginning contains the most relevant context.

### Implementation Locations

1. **`_mode_summarize()`**
   - Before LLM call: `yield Info(message=f"[PROMPT] {_truncate(prompt)}")`
   - After response: `yield Info(message=f"[AGENT] {_truncate(response)}")`

2. **`_mode_suggest()`**
   - Same pattern as summarize

3. **`_mode_attack()`**
   - Same pattern for LLM calls
   - Before command execution: `yield Info(message=f"[CMD] {command}")`
   - After command execution: `yield Info(message=f"[OUTPUT] {_truncate(result_output)}")`

### Verbose Flag

Uses the existing `--verbose` / `-v` flag already defined in the task options. No CLI changes needed.

## Decision Log

- **User prompt only**: Show only the constructed user prompt, not the static system prompt
- **Head truncation**: Truncate from end (not middle) to preserve context flow
- **2000 char limit**: Default truncation length for readability
- **Approach 1 chosen**: Direct yield statements in mode handlers (vs. helper class or LiteLLM callbacks)
