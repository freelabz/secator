# AI Attack Mode Library Execution Design

## Overview

Replace CLI command execution in attack mode with structured JSON responses that are executed via Python bindings. This enables direct integration with secator's Task, Workflow, and Scan runners.

## Scope

- **Attack mode only** - suggest mode keeps CLI command strings for user readability
- **Full runner support** - tasks, workflows, and scans via JSON
- **Shell fallback** - keep curl/wget/nmap direct execution for non-secator commands
- **Option validation** - use `get_config_options()` to validate and give feedback to LLM

## JSON Schema

### Execute Actions

**Secator runners (task/workflow/scan):**
```json
{
  "action": "execute",
  "type": "task|workflow|scan",
  "name": "httpx|host_recon|host",
  "targets": ["target1", "target2"],
  "opts": {"rate_limit": 100, "timeout": 30},
  "reasoning": "why this action",
  "expected_outcome": "what we expect"
}
```

**Shell commands (curl, wget, nmap direct):**
```json
{
  "action": "execute",
  "type": "shell",
  "command": "curl -s http://example.com/path",
  "target": "example.com",
  "reasoning": "why this action",
  "expected_outcome": "what we expect"
}
```

**Other actions (unchanged):**
- `{"action": "validate", ...}` - report validated vulnerability
- `{"action": "complete", ...}` - end attack loop

## Execution Logic

Route execution based on `type` field:

```python
from secator.runners import Task, Workflow, Scan
from secator.template import TemplateLoader

if action["type"] == "task":
    config = TemplateLoader(input={"name": action["name"], "type": "task"})
    runner = Task(config, inputs=action["targets"], **action["opts"])
elif action["type"] == "workflow":
    config = TemplateLoader(name=f"workflows/{action['name']}")
    runner = Workflow(config, inputs=action["targets"], **action["opts"])
elif action["type"] == "scan":
    config = TemplateLoader(name=f"scans/{action['name']}")
    runner = Scan(config, inputs=action["targets"], **action["opts"])

# Yield all results from the runner
for result in runner:
    yield result
```

For shell commands, use existing `_execute_command()` method.

## Option Validation & Feedback Loop

Before executing a secator runner, validate options:

```python
from secator.template import TemplateLoader, get_config_options

# Load config and get valid options
config = TemplateLoader(input={"name": action["name"], "type": action["type"]})
valid_opts = get_config_options(config)
valid_opt_names = [s.replace('-', '_') for s in valid_opts.keys()]

# Check for invalid options
invalid_opts = [k for k in action["opts"].keys() if k not in valid_opt_names]

if invalid_opts:
    # Don't execute - send feedback to LLM
    feedback = f"""Invalid options for {action['type']} '{action['name']}': {invalid_opts}

Valid options are: {valid_opt_names}

Please retry with valid options only."""
    # Continue loop with this feedback as the next prompt
```

## Prompt Changes

Update attack mode system prompt:

1. Replace SECATOR_CHEATSHEET with library-focused reference
2. Update JSON schema examples to show new `type` field
3. Remove CLI syntax references
4. Add runner type explanations

**New prompt structure:**
```
SECATOR RUNNERS:
- task: Single tool execution (httpx, nmap, nuclei, ffuf, etc.)
- workflow: Multi-task pipelines (host_recon, url_crawl, url_fuzz, etc.)
- scan: Comprehensive scans (host, domain, url, etc.)

AVAILABLE TASKS: httpx, nmap, nuclei, ffuf, katana, subfinder, ...
AVAILABLE WORKFLOWS: host_recon, subdomain_recon, url_crawl, url_fuzz, ...
AVAILABLE SCANS: host, domain, url, ...

COMMON OPTIONS: rate_limit, timeout, delay, proxy, ...
```

## Files to Modify

- `secator/tasks/ai.py`:
  - Update `SYSTEM_PROMPTS["attack"]` with new JSON format
  - Add `_execute_secator_runner()` method for Python binding execution
  - Modify `_mode_attack()` to route based on action type
  - Add option validation logic with `get_config_options()`

## Decision Log

- **Library mode for attack only**: suggest mode keeps CLI strings for user readability
- **Unified JSON schema**: single format with `type` field for all action types
- **Shell fallback**: keep direct curl/wget/nmap execution for flexibility
- **Validation feedback**: give LLM valid options list on error instead of failing hard
