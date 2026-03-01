# AI Task DRY Refactor - Phase 1 Design

**Date:** 2026-02-23
**Status:** Approved
**Scope:** Refactor `secator/tasks/ai.py` to reduce complexity and enable future extensibility

## Problem Statement

The `ai.py` file has grown to 3343 lines with significant complexity:
- `_mode_attack` method is 882 lines
- ~30 prompt templates defined inline (~500 lines)
- Repeated patterns in action handling (safety, results, context updates)
- Three separate mode methods with duplicated setup logic

This makes the code hard to navigate, maintain, and extend.

## Goals

1. Reduce file size from ~3343 lines to ~2000 lines
2. DRY out repeated patterns
3. Create extensible structure for Phase 2 (new action types)
4. Keep all existing features working identically

## Non-Goals (Phase 2/3)

- New action types: `query`, `output_type`, `prompt`
- Context management / conversation history
- User interactivity at end of execution
- Subtask tracking via chunked_tasks

## Design

### File Structure

```
ai.py:
├── Imports & Constants
├── AI CLASS (main entry point)
│   ├── opts, __init__
│   ├── yielder() - delegates to _run_mode
│   ├── _run_mode() - unified mode runner
│   ├── _run_action_loop() - iterative execution
│   └── _dispatch_action() - routes to handlers
├── DATA STRUCTURES
│   ├── ActionResult dataclass
│   └── ActionContext dataclass
├── ACTION HANDLERS
│   ├── _handle_execute() → _execute_runner(), _execute_shell()
│   ├── _handle_validate()
│   ├── _handle_complete()
│   ├── _handle_stop()
│   └── (Phase 2 stubs: query, output_type, prompt)
├── HELPER FUNCTIONS
│   ├── Safety: _check_action_safety(), _validate_runner_opts()
│   ├── Results: _collect_action_result(), _update_attack_context()
│   ├── Prompts: _build_initial_prompt(), _build_iteration_prompt()
│   └── Existing helpers (cleaned up)
└── PROMPT TEMPLATES (consolidated, ~15 from ~30)
```

### Data Structures

```python
@dataclass
class ActionResult:
    """Result of executing an action."""
    success: bool
    output: str
    errors: List[str]
    results: List[Any]  # OutputType instances
    context_update: Dict  # What to add to attack_context

@dataclass
class ActionContext:
    """Shared context for action execution."""
    targets: List[str]
    model: str
    api_base: Optional[str]
    temperature: float
    encryptor: SensitiveDataEncryptor
    sensitive: bool
    dry_run: bool
    verbose: bool
    dangerous: bool
    disable_secator: bool
    max_iterations: int
    attack_context: Dict  # successful_attacks, failed_attacks, validated_vulns
```

### Action Handler Pattern

```python
# Registry makes adding new actions trivial
ACTION_HANDLERS = {
    "execute": "_handle_execute",
    "validate": "_handle_validate",
    "complete": "_handle_complete",
    "stop": "_handle_stop",
    # Phase 2 placeholders:
    "query": "_handle_query",
    "output_type": "_handle_output_type",
    "prompt": "_handle_prompt",
}

def _dispatch_action(self, action: Dict, ctx: ActionContext) -> Generator:
    """Dispatch action to appropriate handler."""
    action_type = action.get("action", "")
    handler_name = ACTION_HANDLERS.get(action_type)

    if not handler_name:
        yield Warning(message=f"Unknown action: {action_type}")
        return

    handler = getattr(self, handler_name, None)
    if not handler:
        yield Warning(message=f"Handler not implemented: {action_type}")
        return

    yield from handler(action, ctx)
```

### Unified Mode System

```python
MODE_CONFIG = {
    "summarize": {
        "iterative": False,
        "system_prompt": PROMPT_SUMMARIZE,
        "response_type": "summary",
    },
    "suggest": {
        "iterative": False,
        "system_prompt": PROMPT_SUGGEST,
        "response_type": "suggestion",
    },
    "attack": {
        "iterative": True,
        "system_prompt": PROMPT_ATTACK,
        "allowed_actions": ["execute", "validate", "complete", "stop"],
    },
}

def _run_mode(self, mode: str, ctx: ActionContext) -> Generator:
    """Unified mode runner - handles all modes."""
    config = MODE_CONFIG[mode]
    prompt = self._build_initial_prompt(mode, ctx)
    system_prompt = self._build_system_prompt(mode, ctx)

    if not config["iterative"]:
        # One-shot modes (summarize, suggest)
        response = get_llm_response(prompt, ctx.model, system_prompt, ...)
        yield AI(content=response, ai_type=config["response_type"], mode=mode)
    else:
        # Iterative mode (attack)
        yield from self._run_action_loop(prompt, system_prompt, ctx, config)
```

### Extracted Sub-Patterns

| Method | Purpose | Lines |
|--------|---------|-------|
| `_check_action_safety()` | Unified safety check for runners and shell | ~30 |
| `_execute_runner()` | Execute task/workflow/scan | ~80 |
| `_execute_shell()` | Execute shell command | ~50 |
| `_collect_action_result()` | Build ActionResult from execution | ~20 |
| `_update_attack_context()` | Update context with results | ~20 |
| `_format_batch_results()` | Format results for LLM | ~30 |

### Prompt Consolidation

| Before | After |
|--------|-------|
| `PROMPT_ATTACK` + `PROMPT_ATTACK_SHELL_ONLY` | `PROMPT_ATTACK` with conditionals |
| `PROMPT_ATTACK_START_NO_RESULTS` + `PROMPT_ATTACK_START_WITH_RESULTS` | `PROMPT_ATTACK_START` |
| `PROMPT_ANALYZE_TARGETS` + `PROMPT_ANALYZE_RESULTS` | `PROMPT_ANALYZE` |
| `PROMPT_SUGGEST_TARGETS` + `PROMPT_SUGGEST_RESULTS` | `PROMPT_SUGGEST` |

Prompts move to bottom of file for better code navigation.

## Metrics

| Area | Before | After |
|------|--------|-------|
| Total file | 3343 lines | ~2000 lines |
| Mode methods | 1077 lines (3 methods) | ~180 lines (unified) |
| `_mode_attack` | 882 lines | ~100 lines |
| Prompt templates | ~30 (~500 lines) | ~15 (~300 lines) |
| Action handling | Nested if/elif (400+ lines) | Handler dispatch (~50 lines + handlers) |

## Testing Strategy

1. All existing unit tests must pass
2. Integration tests for attack mode unchanged
3. Manual verification of all three modes
4. Compare outputs before/after refactor

## Migration Path

1. Create new structure alongside existing code
2. Migrate one mode at a time (summarize → suggest → attack)
3. Remove old code once all modes migrated
4. Update any tests that reference internal methods

## Future Work (Phase 2/3)

**Phase 2: New Action Types**
- `query`: Workspace queries via QueryEngine
- `output_type`: Convert shell output to Secator types
- `prompt`: Ask user for direction (non-CI only)

**Phase 3: Context & Interactivity**
- Conversation history management
- Auto-trim context when too large
- User input at end of execution path
- Subtask tracking via chunked_tasks
