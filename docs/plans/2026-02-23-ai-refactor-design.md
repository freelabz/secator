# AI Task Refactor Design

## Goal

Simplify `secator/tasks/ai.py` from ~4000 lines to ~300 lines by extracting concerns into focused modules, using litellm's native message format, and streamlining prompts.

## Architecture

### Module Structure

```
secator/tasks/
├── ai.py                 (~250-300 lines) - Main Ai Task, run loop
├── ai_actions.py         (~150-200 lines) - Action handlers
├── ai_prompts.py         (~100-150 lines) - Prompt templates
├── ai_history.py         (refactor)       - Simplify to list wrapper
├── ai_prompt_builder.py  (refactor)       - Align with litellm format
└── ai_encryption.py      (~80 lines)      - SensitiveDataEncryptor
```

### Two Modes

1. **attack** - Iterative security testing loop with actions (task, workflow, scan, shell, query, done)
2. **chat** - Interactive Q&A with workspace queries and analysis

### Message Format (litellm native)

All messages follow litellm's conversation format:

```python
messages = [
    {"role": "system", "content": "<system prompt>"},
    {"role": "user", "content": '{"targets":["example.com"],"instructions":"..."}'},
    {"role": "assistant", "content": "Reasoning here.\n\n```json\n[{...}]\n```"},
    {"role": "user", "content": '{"tool_results":[...]}'},
]
```

**Key principles:**
- User messages: JSON (no whitespace for token efficiency)
- Assistant messages: Markdown reasoning + JSON action array
- Tool results: Compact JSON in user messages

### Response Format

LLM responses have two parts:
1. Markdown explanation (displayed to user)
2. JSON action array (parsed for execution)

```
Brief reasoning about the approach.

```json
[{"action":"task","name":"nmap","targets":["[HOST:abc123]"],"opts":{}}]
```
```

### Encryption Flow

1. Encrypt targets/hosts before adding to messages
2. LLM works with encrypted placeholders `[HOST:xxxx]`
3. Decrypt after receiving response, before execution
4. All tool results use encrypted format

### Data Flow

```
User Input
    ↓
Encrypt (targets, hosts, IPs)
    ↓
Intent Analysis (attack/chat?)
    ↓
Build messages list
    ↓
completion(model, messages)
    ↓
Parse response (markdown + JSON)
    ↓
Decrypt action parameters
    ↓
Execute actions / Display to user
    ↓
Add tool results to messages
    ↓
Loop until done
```

## Prompt Templates

### System Prompt (attack mode)

~400 tokens, focused on action format and rules:

```python
SYSTEM_ATTACK = """Security testing assistant. Execute actions against provided targets.

RESPONSE FORMAT:
1. Brief reasoning (2-3 sentences max)
2. JSON array of actions

ACTIONS:
- task: {"action":"task","name":"<tool>","targets":[...],"opts":{}}
- workflow: {"action":"workflow","name":"<name>","targets":[...]}
- shell: {"action":"shell","command":"<cmd>"}
- query: {"action":"query","type":"<output_type>","filter":{}}
- done: {"action":"done","reason":"<why>"}

RULES:
- One action array per response
- Never invent tool output
- Use query to check results before concluding
- Targets are encrypted as [HOST:xxxx] - use as-is

AVAILABLE TOOLS: {tools}
AVAILABLE WORKFLOWS: {workflows}"""
```

### System Prompt (chat mode)

~200 tokens:

```python
SYSTEM_CHAT = """Security assistant for workspace queries and analysis.

RESPONSE FORMAT: Markdown explanation, then optional JSON action.

ACTIONS:
- query: {"action":"query","type":"<type>","filter":{}}
- done: {"action":"done"}

Answer questions using workspace data. Use query action to fetch data."""
```

### User Messages

Initial (JSON, no whitespace):
```python
USER_INITIAL = '{"targets":{targets},"instructions":"{instructions}"}'
```

Tool results (JSON):
```python
TOOL_RESULT = '{{"task":"{name}","status":"{status}","count":{count},"sample":{sample}}}'
```

Continue prompt:
```python
USER_CONTINUE = '{"iteration":{n},"max":{max},"instruction":"continue"}'
```

## Module Responsibilities

### ai.py (~300 lines)

- `Ai` Task class definition
- `run()` method with mode dispatch
- `_run_attack()` - attack loop
- `_run_chat()` - chat loop
- `_call_llm()` - litellm completion wrapper
- `_parse_response()` - extract markdown + JSON
- Token/cost tracking and display

### ai_actions.py (~200 lines)

- `dispatch_action(action, ctx)` - route to handler
- `handle_task(action, ctx)` - run secator task
- `handle_workflow(action, ctx)` - run workflow
- `handle_shell(action, ctx)` - run shell command
- `handle_query(action, ctx)` - workspace query
- `handle_done(action, ctx)` - completion

### ai_prompts.py (~150 lines)

- `SYSTEM_ATTACK` - attack mode system prompt
- `SYSTEM_CHAT` - chat mode system prompt
- `USER_INITIAL` - initial user message template
- `TOOL_RESULT` - tool result template
- `USER_CONTINUE` - continue iteration template
- `get_system_prompt(mode)` - build with tool/workflow lists

### ai_encryption.py (~80 lines)

- `SensitiveDataEncryptor` class (move from ai.py)
- `encrypt(text)` - replace hosts/IPs with placeholders
- `decrypt(text)` - restore original values

### ai_history.py (refactor)

Simplify to thin wrapper around message list:

```python
class ChatHistory:
    def __init__(self):
        self.messages = []

    def add_system(self, content): ...
    def add_user(self, content): ...
    def add_assistant(self, content): ...
    def to_messages(self) -> list: ...
```

### ai_prompt_builder.py (refactor)

Align with new format:

```python
class PromptBuilder:
    def build_system(self, mode): ...
    def build_user_initial(self, targets, instructions): ...
    def build_tool_result(self, name, status, count, sample): ...
    def build_continue(self, iteration, max_iterations): ...
```

## Token/Cost Display

Every LLM call displays:
- Input tokens (with arrow up icon)
- Output tokens (with arrow down icon)
- Cost estimate

```python
response = completion(model=model, messages=messages)
usage = response.usage
yield Ai(
    content="...",
    ai_type="response",
    extra_data={
        "tokens": usage.total_tokens,
        "cost": calculate_cost(model, usage)
    }
)
```

## Success Criteria

1. ai.py reduced to ~300 lines
2. Two modes work: attack and chat
3. All messages use litellm format
4. Encryption/decryption works correctly
5. Token/cost displayed on all LLM calls
6. No hallucination issues
7. Existing tests pass or are updated
