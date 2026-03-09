# Native Tool Calling for Secator AI

**Date:** 2026-03-08
**Status:** Approved

## Problem

Secator AI uses regex-based JSON parsing to extract actions from freeform LLM text (`parse_actions` in `secator/ai/utils.py`). This is fragile — every other comparable framework (CAI, pentestagent, Pentagi, HolmesGPT) uses native LLM tool calling. The current approach fails on malformed JSON, partial responses, and models that don't consistently format JSON.

## Decision

Replace freeform JSON parsing with litellm's native tool calling protocol. Define 6 tools mapping 1:1 to existing action handlers.

## Tool Definitions

| Tool | Maps to handler | Key parameters |
|------|----------------|---------------|
| `run_task` | `_handle_task` | `name`, `targets`, `opts` |
| `run_workflow` | `_handle_workflow` | `name`, `targets`, `opts` |
| `run_shell` | `_handle_shell` | `command` |
| `query_workspace` | `_handle_query` | `query`, `limit` |
| `follow_up` | `_handle_follow_up` | `reason`, `choices` |
| `add_finding` | `_handle_add_finding` | `_type`, plus dynamic fields |

## Data Flow

```
call_llm(messages, model, tools=TOOL_SCHEMAS)
  -> response.choices[0].message
      |-- .content -> display as reasoning (Ai type="response")
      |-- .tool_calls -> list of structured calls
          |-- 1 call -> dispatch_action(single)
          |-- 2+ calls -> _run_batch(all)

For each tool call result:
  -> history: assistant message with tool_calls + tool role result messages
  -> runner: yield findings, Ai outputs, self.add_result() (unchanged)
```

## File Changes

### New: `secator/ai/tools.py`
Tool schema definitions in OpenAI function-calling format. `build_tool_schemas(mode)` returns only the tools allowed for that mode (using `MODES[mode]["allowed_actions"]`).

### Modified: `secator/ai/utils.py`
- `call_llm` passes `tools` parameter to `litellm.completion()`, returns `tool_calls` from response alongside `content` and `usage`
- Remove `parse_actions`, `strip_json_from_response`, `_find_matching_bracket`, `_is_action_list`

### Modified: `secator/ai/history.py`
- `ChatHistory` gains methods for adding assistant messages with `tool_calls` and `tool` role result messages
- `maybe_summarize` handles tool message shapes

### Modified: `secator/tasks/ai.py`
- `_run_loop` processes `response.tool_calls` instead of `parse_actions(response)`
- Multiple tool_calls in one response -> `_run_batch`; single -> `dispatch_action`
- Display: `content` displayed as-is, no stripping

### Modified: `secator/ai/prompts.py`
- Remove TEMPLATE and EXAMPLES sections from all mode prompts (tool schemas replace them)
- Keep PERSONA, ACTION, STEPS, CONTEXT, CONSTRAINTS
- Remove JSON-formatting instructions from CONSTRAINTS

### Modified: `secator/ai/actions.py`
- Remove `group_actions` (native multi-tool-call replaces it)
- Remove `group` field handling

## Parallel Execution

Native multi-tool-call replaces the `group` field mechanism. When `len(tool_calls) >= 2`, all calls go through `_run_batch` (existing ThreadPoolExecutor). Each tool call gets its own `tool` role result message. Tool call IDs from the response are preserved (required by protocol).

## Error Handling

- **No tool_calls and no content**: Warning, continue loop
- **No tool_calls but has content**: Text-only response. Display as `Ai(ai_type="response")`. In attack/exploiter: send continue. In chat: trigger follow_up menu.
- **Malformed tool arguments**: `json.loads` fails -> yield Error, add error as tool result so LLM can retry
- **Unknown function name**: yield Warning, add error as tool result

## Model Compatibility

Litellm handles tool calling compatibility across providers. We always pass `tools` and let litellm figure out native vs simulated tool calling. No custom fallback code needed.

## Token Budget

Tool schemas add ~500-800 tokens overhead. Removing TEMPLATE+EXAMPLES sections saves ~400+ tokens. Net impact roughly neutral.

## What Stays the Same

- `dispatch_action` and all action handlers in `actions.py`
- `_run_batch` (used when 2+ tool_calls)
- `ActionContext` dataclass
- Runner yielding pipeline (Ai outputs, findings, self.add_result)
- Encryption (decrypt tool call arguments instead of response text)
- Mode system (MODES dict, get_mode_config)
