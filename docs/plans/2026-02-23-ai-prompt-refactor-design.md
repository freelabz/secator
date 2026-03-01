# AI Prompt Structure Refactor

**Date:** 2026-02-23
**Status:** Approved
**Scope:** Refactor AI attack mode prompts for clarity and consistent encryption

## Problem Statement

The current AI attack mode has several issues:
1. Prompts mix context and instructions in ad-hoc ways
2. The AI loses track of previous actions (e.g., repeated queries)
3. Encryption is scattered across multiple code paths, with some data bypassing encryption
4. Hard to audit and maintain

## Goals

1. Clear prompt structure: System → User → History → Current Query
2. Accumulated chat history with periodic summarization
3. Single encryption gate at the edge
4. Cleaner, more maintainable code

## Design

### Prompt Structure

```
┌─────────────────────────────────────────┐
│ SYSTEM PROMPT                           │
│ - Role definition                       │
│ - Action schemas (execute, query, etc.) │
│ - Available tools/capabilities          │
│ - Output format requirements            │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ USER PROMPT                             │
│ - Original user instructions            │
│ - Targets                               │
│ - Custom prompt suffix                  │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CHAT HISTORY                            │
│ - Summary of older iterations (if any)  │
│ - Last 2 iterations verbatim            │
│   [{"role": "assistant", "content":...} │
│    {"role": "tool", "content": ...}]    │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CURRENT LOOP QUERY                      │
│ - Current iteration number              │
│ - What to do next                       │
└─────────────────────────────────────────┘
```

### Chat History Format

Role-based messages (OpenAI-style):
- `{"role": "assistant", "content": <LLM response>}`
- `{"role": "tool", "content": <action results>}`
- `{"role": "user", "content": <user input>}` (at checkpoints)

### Summarization

**Timing:** At checkpoints (every `prompt_iterations` iterations)

**Process:**
1. Keep last 2 iterations verbatim
2. Send older iterations to summary model
3. Replace older iterations with single summary message

**Model:** Configurable via `--summary-model` (default: same as `--model`)

**Example after checkpoint at iteration 5:**
```json
[
  {"role": "system", "content": "## Summary of iterations 1-3\n\n**Reconnaissance:**\n- Ran nmap: found ports 22, 80, 443\n- Ran httpx: confirmed nginx/1.19.0\n\n**Findings:**\n- CVE-2019-11043 (PHP-FPM RCE)"},
  {"role": "assistant", "content": "<iteration 4 response>"},
  {"role": "tool", "content": "<iteration 4 results>"},
  {"role": "assistant", "content": "<iteration 5 response>"},
  {"role": "tool", "content": "<iteration 5 results>"}
]
```

### Encryption at the Edge

**Current problem:** Encryption scattered, some paths miss encryption.

**New approach:**
- All context assembled in plaintext internally
- Single encryption point in `_build_prompt()` before LLM call
- Single decryption point on LLM response

```python
def _build_prompt(self, ctx, history, current_query):
    """Build complete prompt, encrypt if sensitive mode."""
    prompt = {
        "system": self._build_system_prompt(),
        "user": self._build_user_prompt(ctx),
        "history": history,
        "query": current_query,
    }

    if ctx.sensitive:
        prompt = self._encrypt_prompt(prompt, ctx.encryptor)

    return prompt

def _handle_response(self, response, ctx):
    """Handle LLM response, decrypt if needed."""
    if ctx.sensitive:
        response = ctx.encryptor.decrypt(response)
    return self._parse_actions(response)
```

### New Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        ChatHistory                               │
│  - messages: List[{"role": str, "content": str}]                │
│  - add_assistant(content) → append assistant message            │
│  - add_tool(content) → append tool message                      │
│  - add_user(content) → append user message                      │
│  - summarize(model, keep_last=2) → compress older messages      │
│  - to_messages() → return formatted message list                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       PromptBuilder                              │
│  - build_system_prompt() → static system prompt                 │
│  - build_user_prompt(ctx) → targets + instructions              │
│  - build_loop_query(iteration, max) → current iteration prompt  │
│  - build_full_prompt(ctx, history) → assembled prompt           │
│  - encrypt_prompt(prompt, encryptor) → encrypt all fields       │
└─────────────────────────────────────────────────────────────────┘
```

### Attack Loop Flow

```
1. Initialize ChatHistory()
2. For each iteration:
   a. Build prompt via PromptBuilder.build_full_prompt(ctx, history)
   b. Encrypt at edge if sensitive
   c. Send to LLM
   d. Decrypt response if sensitive
   e. Parse actions
   f. Execute actions, collect results
   g. history.add_assistant(response)
   h. history.add_tool(formatted_results)
   i. At checkpoint: history.summarize(summary_model, keep_last=2)
```

### Error Handling

**Context overflow prevention:**
- Track approximate token count in ChatHistory
- Force summarization if history exceeds 80% of context window
- Warn user if summary itself is too large

**Summarization failures:**
- Fall back to template extraction (commands run, findings found)
- Log warning but don't break attack loop

**Empty history:**
- First iteration skips history section entirely

**User messages at checkpoints:**
- Add as `{"role": "user", "content": "..."}` in history

**Encryption edge cases:**
- If encryptor fails, abort with clear error (don't send unencrypted)
- Summary model also receives encrypted data if sensitive mode

### New CLI Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--summary-model` | str | same as `--model` | Model for history summarization |

## Summary of Decisions

| Aspect | Decision |
|--------|----------|
| Prompt structure | System → User → History → Current Query |
| History format | Role-based messages (OpenAI-style) |
| Summarization timing | At checkpoints (`prompt_iterations`) |
| Summarization method | LLM-generated |
| Summary model | Configurable via `--summary-model` |
| Verbatim window | Last 2 iterations |
| Encryption | Single gate at edge |
| New components | `ChatHistory`, `PromptBuilder` |
