# AI Task Checkpoint & Continuation System

**Date:** 2026-02-23
**Status:** Approved
**Scope:** Add periodic user checkpoints and end-of-loop continuation to AI attack mode

## Problem Statement

Long-running AI attack sessions can drift from user intent. Users need:
1. Periodic opportunities to re-orient the LLM during execution
2. Ability to continue interacting after the attack loop completes

## Goals

1. Add `--prompt-iterations` option for periodic user checkpoints
2. Default to `min(max_iterations // 2, 5)` iterations between prompts
3. Add end-of-loop continuation prompt
4. Skip all prompts in CI/auto_yes mode

## Design

### New CLI Option

```python
"prompt_iterations": {
    "type": int,
    "default": None,  # Calculated at runtime
    "help": "Prompt user for direction every N iterations (default: min(max_iterations/2, 5))",
}
```

### Default Calculation

```python
prompt_iterations = self.run_opts.get("prompt_iterations")
if prompt_iterations is None:
    prompt_iterations = min(max_iterations // 2, 5)
```

### Periodic Checkpoint Logic

At the start of each iteration in `_mode_attack`:

```python
for iteration in range(max_iterations):
    # Periodic checkpoint (skip first iteration, skip in CI/auto_yes)
    if iteration > 0 and iteration % prompt_iterations == 0:
        if not ctx.in_ci and not ctx.auto_yes:
            checkpoint_result = yield from self._prompt_checkpoint(iteration, ctx)
            if checkpoint_result == "stop":
                break
            elif checkpoint_result == "change":
                # User provided new instructions, rebuild prompt
                prompt = self._build_iteration_prompt(ctx, checkpoint_result)

    # ... rest of iteration logic
```

### Checkpoint Prompt

```python
def _prompt_checkpoint(self, iteration: int, ctx: ActionContext) -> Generator:
    """Prompt user at periodic checkpoint.

    Returns:
        "continue", "stop", or new instructions string
    """
    checkpoint_action = {
        "action": "prompt",
        "question": f"Checkpoint at iteration {iteration + 1}/{ctx.max_iterations}. How should I proceed?",
        "options": [
            "Continue attacking",
            "Change direction",
            "Stop and summarize"
        ],
        "default": "Continue attacking",
    }

    yield from self._handle_prompt(checkpoint_action, ctx)

    user_response = ctx.attack_context.get("user_response", "Continue attacking")

    if "Stop" in user_response:
        return "stop"
    elif "Change" in user_response:
        from rich.prompt import Prompt
        new_instructions = Prompt.ask("[bold cyan]New instructions[/]")
        return new_instructions
    else:
        return "continue"
```

### End-of-Loop Continuation

After the main attack loop completes (max_iterations reached, `complete`, or `stop`):

```python
# End-of-loop continuation (skip in CI/auto_yes)
if not ctx.in_ci and not ctx.auto_yes:
    while True:
        continuation_result = yield from self._prompt_continuation(ctx)

        if continuation_result == "stop":
            break
        elif continuation_result == "continue":
            # Run another batch of prompt_iterations
            for iteration in range(prompt_iterations):
                # ... attack iteration logic
        else:
            # New instructions provided
            prompt = self._build_iteration_prompt(ctx, continuation_result)
            for iteration in range(prompt_iterations):
                # ... attack iteration logic with new prompt

# Generate final summary
yield from self._generate_final_summary(ctx)
```

### Continuation Prompt

```python
def _prompt_continuation(self, ctx: ActionContext) -> Generator:
    """Prompt user for continuation after loop ends.

    Returns:
        "continue", "stop", or new instructions string
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

    user_response = ctx.attack_context.get("user_response", "Stop")

    if "Stop" in user_response:
        return "stop"
    elif "Continue" in user_response:
        return "continue"
    else:
        from rich.prompt import Prompt
        new_instructions = Prompt.ask("[bold cyan]New instructions[/]")
        return new_instructions
```

### CI/auto_yes Behavior

All checkpoints and continuation prompts are skipped:
- Periodic checkpoints: Skip silently
- End-of-loop: Auto-generate report and exit

### ActionContext Update

Add `max_iterations` to ActionContext for use in prompts:

```python
@dataclass
class ActionContext:
    # ... existing fields
    max_iterations: int = 10
```

## Metrics

| Change | Lines |
|--------|-------|
| New CLI option | ~5 |
| `_prompt_checkpoint()` | ~25 |
| `_prompt_continuation()` | ~25 |
| Attack loop integration | ~30 |
| End-of-loop continuation loop | ~20 |
| **Total** | **~105** |

## Testing Strategy

1. Unit tests for `_prompt_checkpoint` and `_prompt_continuation`
2. Test CI mode skips checkpoints
3. Test default calculation: `min(max_iterations // 2, 5)`
4. Integration test with mock prompts
