# AI Task Phase 2: New Action Types

**Date:** 2026-02-23
**Status:** Approved
**Scope:** Add query, output_type, and prompt action handlers to AI attack mode

## Problem Statement

Phase 1 established the handler dispatch pattern with `ACTION_HANDLERS` registry. Phase 2 implements three new action types that extend AI capabilities:

1. **query**: Fetch workspace results during attack execution
2. **output_type**: Convert shell output to structured Secator OutputTypes
3. **prompt**: Ask user for direction (interactive mode only)

## Goals

1. Add three new action handlers following Phase 1 patterns
2. Enable AI to query workspace via existing QueryEngine
3. Allow AI to create structured findings from raw output
4. Support user interaction during attack execution (when not in CI)

## Non-Goals

- Modifying QueryEngine implementation
- Adding new OutputTypes
- Context management / conversation history (Phase 3)

## Design

### Action 1: query

**Purpose:** Allow AI to query workspace results during attack execution.

**Action Schema (from LLM):**
```json
{
  "action": "query",
  "query": {"_type": "vulnerability", "severity": {"$in": ["critical", "high"]}},
  "result_key": "critical_vulns",
  "reasoning": "Fetch critical vulnerabilities to prioritize exploitation"
}
```

**Handler Logic:**
1. Get workspace context from ActionContext
2. Call `QueryEngine(workspace_id, context).search(query)`
3. Format results as string for LLM context
4. Add to `attack_context[result_key]`
5. Yield `Info` with query summary

**Handler Implementation:**
```python
def _handle_query(self, action: dict, ctx: ActionContext) -> Generator:
    """Handle query action - fetch workspace results."""
    query = action.get("query", {})
    result_key = action.get("result_key", "query_results")
    reasoning = action.get("reasoning", "")

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
```

### Action 2: output_type

**Purpose:** Convert shell command output to structured Secator OutputTypes.

**Action Schema (from LLM):**
```json
{
  "action": "output_type",
  "output": "Found SQL injection at /login?user=admin",
  "output_type": "vulnerability",
  "fields": {
    "name": "SQL Injection",
    "severity": "high",
    "matched_at": "https://target.com/login?user=admin",
    "confidence": "high"
  },
  "reasoning": "Convert manual finding to structured vulnerability"
}
```

**Handler Logic:**
1. Validate `output_type` is a known type
2. Import the OutputType class dynamically
3. Create instance with provided fields
4. Yield the OutputType instance

**Supported OutputTypes:**
- Vulnerability, Exploit (findings)
- Port, Url, Subdomain, Ip, Domain (infrastructure)
- Tag, Record, Certificate, UserAccount (metadata)

**Handler Implementation:**
```python
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

def _handle_output_type(self, action: dict, ctx: ActionContext) -> Generator:
    """Handle output_type action - convert output to structured type."""
    output_type = action.get("output_type", "").lower()
    fields = action.get("fields", {})
    reasoning = action.get("reasoning", "")

    # Validate output type
    if output_type not in OUTPUT_TYPE_MAP:
        yield Warning(message=f"Unknown output_type: {output_type}. Valid: {list(OUTPUT_TYPE_MAP.keys())}")
        return

    # Import and create instance
    try:
        class_name = OUTPUT_TYPE_MAP[output_type]
        module = __import__(f"secator.output_types.{output_type}", fromlist=[class_name])
        OutputClass = getattr(module, class_name)

        # Add source metadata
        fields['_source'] = 'ai'

        instance = OutputClass(**fields)
        yield instance

    except Exception as e:
        yield Error(message=f"Failed to create {output_type}: {e}")
```

### Action 3: prompt

**Purpose:** Ask user for direction during attack execution (interactive mode only).

**Action Schema (from LLM):**
```json
{
  "action": "prompt",
  "question": "Found 15 SQLi endpoints. How should I proceed?",
  "options": ["Exploit all", "Exploit critical only", "Skip exploitation", "Let me choose targets"],
  "default": "Exploit critical only",
  "reasoning": "Need user guidance on exploitation scope"
}
```

**Handler Logic:**
1. Check if interactive mode (`not ctx.in_ci and not ctx.auto_yes`)
2. If not interactive: yield Warning, use default, continue
3. If interactive: display question with rich prompt
4. Wait for user input
5. Return selected option in ActionResult for LLM to process

**Handler Implementation:**
```python
def _handle_prompt(self, action: dict, ctx: ActionContext) -> Generator:
    """Handle prompt action - ask user for direction."""
    question = action.get("question", "")
    options = action.get("options", [])
    default = action.get("default", options[0] if options else "")
    reasoning = action.get("reasoning", "")

    # Display the question
    yield AI(content=question, ai_type="prompt", extra_data={"options": options})

    # Check if interactive
    if ctx.in_ci or ctx.auto_yes:
        yield Info(message=f"Auto-selecting: {default} (non-interactive mode)")
        ctx.attack_context["user_response"] = default
        return

    # Interactive prompt
    try:
        from rich.prompt import Prompt

        # Build choices display
        choices_str = " / ".join(f"[{i+1}] {opt}" for i, opt in enumerate(options))

        response = Prompt.ask(
            f"[bold cyan]Choose[/] ({choices_str})",
            choices=[str(i+1) for i in range(len(options))] + options,
            default="1"
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

### Changes to ActionContext

Add workspace fields:
```python
@dataclass
class ActionContext:
    # ... existing fields ...
    workspace_id: str = None
    workspace_name: str = None
    drivers: list = field(default_factory=list)
```

### Changes to ACTION_HANDLERS

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

### System Prompt Additions

Add to attack mode system prompt:
```
## Additional Actions (Phase 2)

### query
Query workspace for existing findings. Requires -ws flag.
{
  "action": "query",
  "query": {"_type": "...", "field": {"$operator": "value"}},
  "result_key": "unique_key_for_results",
  "reasoning": "why you need this data"
}

Query operators: $in, $regex, $contains, $gt, $gte, $lt, $lte, $ne

### output_type
Convert findings to structured Secator output types.
{
  "action": "output_type",
  "output": "raw output or description",
  "output_type": "vulnerability|port|url|subdomain|ip|exploit|tag",
  "fields": {
    "name": "required for most types",
    "severity": "critical|high|medium|low|info",
    "matched_at": "where it was found",
    ...
  },
  "reasoning": "why creating this output"
}

### prompt
Ask user for direction (skipped in CI/auto mode).
{
  "action": "prompt",
  "question": "What should I do?",
  "options": ["Option A", "Option B", "Option C"],
  "default": "Option A",
  "reasoning": "why user input needed"
}
```

## Metrics

| Area | Lines Added |
|------|-------------|
| `_handle_query()` | ~40 |
| `_handle_output_type()` | ~50 |
| `_handle_prompt()` | ~60 |
| `_format_query_results()` | ~20 |
| `OUTPUT_TYPE_MAP` constant | ~15 |
| ActionContext changes | ~5 |
| ACTION_HANDLERS update | ~3 |
| System prompt additions | ~40 |
| **Total** | **~230** |

## Testing Strategy

1. **Unit Tests:**
   - `_handle_query()` with mock QueryEngine
   - `_handle_output_type()` for each supported type
   - `_handle_prompt()` in CI mode (auto-select)

2. **Integration Tests:**
   - Query action with real workspace
   - output_type action yielding real OutputTypes
   - prompt action with mock user input

3. **Manual Testing:**
   - Full attack flow using new actions
   - CI mode auto-selection
   - Error handling for invalid queries/types

## Future Work (Phase 3)

- Context management / conversation history
- Auto-trim context when too large
- Subtask tracking via chunked_tasks
