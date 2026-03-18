# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Secator is a Python-based security assessment automation framework ("the pentester's swiss knife") that integrates 40+ security tools into a unified CLI. It provides standardized input/output across tools, workflow composition via YAML, and distributed execution via Celery or Airflow.

## Prerequisites

Before running any `secator` command (including tests, installs, and task execution), activate the virtualenv:

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
```

## Common Commands

```bash
# Development setup
git clone https://github.com/freelabz/secator && cd secator
virtualenv .venv && source .venv/bin/activate
pip install -e .[dev]

# Testing
secator test unit                                    # Run all unit tests
secator test unit --task <TASK_NAME> --test test_tasks  # Test specific task
secator test integration --test test_tasks           # Integration tests
secator test integration --test test_workflows --workflows <NAME>
secator test integration --test test_scans --scans <NAME>
secator test lint                                    # Run flake8 linting

# Running secator
secator x <task> <target>                           # Run a task (aliases: task, t)
secator w <workflow> <target>                       # Run a workflow
secator s <scan> <target>                           # Run a scan
secator health                                      # Check installed tools
secator cheatsheet                                  # Command reference

# Worker mode (distributed execution)
secator worker                                      # Start Celery worker
secator worker -r                                   # Worker with auto-reload
```

## Architecture

### Runner Hierarchy
The core abstraction is `Runner` (`secator/runners/_base.py`) with subclasses:
- **Command** (`command.py`): Executes external CLI tools, handles output parsing, installation
- **Task** (`task.py`): Single tool execution with hooks
- **Workflow** (`workflow.py`): Composes multiple tasks from YAML
- **Scan** (`scan.py`): Higher-level composition of workflows

### Task Implementation Pattern
Each integrated tool (nmap, httpx, nuclei, etc.) is a `Command` subclass in `secator/tasks/`. Required attributes:
- `cmd`: Command name
- `input_type`: Input data type (HOST, URL, etc.)
- `output_types`: List of OutputType classes produced
- `install_cmd`: Auto-installation command
- Custom parsers via `item_loaders`

### Output Type System
Standardized result models in `secator/output_types/`:
- **Findings**: Domain, Subdomain, Ip, Port, Url, Vulnerability, Exploit, Certificate
- **Execution**: Target, Progress, Info, Warning, Error, State
- All inherit from `OutputType` base class with serialization and deduplication

### Configuration
- **YAML configs** in `secator/configs/`: workflows, scans, profiles
- **Pydantic config** in `secator/config.py`: runtime settings
- Profiles (aggressive, passive, stealth) apply option presets to tasks

### Distribution Backends
- **Sync**: Direct Python execution
- **Celery** (`secator/celery*.py`): Task queue with Redis/filesystem broker
- **Airflow** (`secator/airflow/`): DAG-based orchestration (requires Airflow >= 3.0)

## Key Directories

| Path | Purpose |
|------|---------|
| `secator/tasks/` | Tool integrations (~45 tasks) |
| `secator/runners/` | Runner implementations |
| `secator/output_types/` | Result data models |
| `secator/configs/workflows/` | Workflow YAML definitions |
| `secator/configs/scans/` | Scan YAML definitions |
| `secator/configs/profiles/` | Option presets (aggressive, stealth, etc.) |
| `secator/exporters/` | Output formats (CSV, JSON, GDrive) |
| `secator/serializers/` | Tool output parsers |
| `tests/fixtures/` | Tool output fixtures for testing |

## Adding New Tools

1. Create task file in `secator/tasks/<tool_name>.py` as `Command` subclass
2. Define `input_type`, `output_types`, `install_cmd`
3. Add fixture in `tests/fixtures/<tool_name>_output.(json|xml|txt)`
4. Add test inputs/outputs in `tests/integration/inputs.py` and `outputs.py`
5. Run: `secator test unit --task <TASK_NAME> --test test_tasks`

## Adding Workflows/Scans

1. Create YAML file in `secator/configs/workflows/` or `secator/configs/scans/`
2. Ensure `name` matches filename, `type` is `workflow` or `scan`
3. Add test cases in `tests/integration/inputs.py` and `outputs.py`
4. Run: `secator test integration --test test_workflows --workflows <NAME>`

## Testing & Linting

Always use `secator` commands to run tests (not `pytest` directly):

```bash
secator test lint                                    # Run flake8 linting
secator test unit                                    # Run all unit tests
secator test unit --test <test_name_or_regex>         # Run specific unit test(s)
```

Flake8 config (`.flake8`): max-line-length=120, ignores W191, E101, E128, E265, W605

## Coding guidelines

### Don't repeat yourself
We should keep code DRY in a reasonable way:
BAD, should refactor:
- More than 2 repeated code blocks of more than 5 lines
- More than 10 repeated code blocks of less than 3 lines

**Note:** We consider a repeated code block not an exact copy, it can have some variations, a.k.a only a few variables / if statements change between the code blocks.

### Long methods and functions
Long methods or functions are fine, as they allow us to understand a whole flow.
However, when long methods include too many blocks not required to understand the flow, those blocks should be refactored into their own methods.
If some blocks are re-used more than 2 times inside the same long method, refactor into a method.

### Instance methods
If within a class, we should thrive to not repeat too much the input arguments, and write instance methods that use self.<key> attributes instead.
This cleans up the overall flow and allows us to reason on the object instead of function input arguments.
When an instance method takes many arguments that should have belonged to to the instance method instead, refactor those to be self.<key> attributes.

### Inheritance vs composition
We can use inheritance reasonably, and already do, but should avoid to overuse it, and prefer composition if it grows too much (more than 3 children for a defined base class).

### Task integration
We should keep modules in secator/tasks/*.py to a reasonable size (no more than 500 lines).

## Adding new Secator tasks

When adding new Secator tasks (e.g: nmap):

### Commands
If you want to implement a new Command task (a task that will call another binary):
* First make sure to install it.
* Then, make sure to run `-h`, `--help`, or `help` on it so that you understand all the options. Pick options that should be supported by secator, leave out the rest (too-specific, format-related options, management-related options, etc...).
* Read all the other tasks in `secator/tasks/` to understand how we process commands supporting JSON, commands not supporting JSON (only plaintext output), and commands outputting JSON in files that we parse afterwards.
* Make sure to add `json_flag` if your task supports JSON-lines or JSON output to file
* If options can be mutualized with other tasks, make sure to use the proper subclass for the task (e.g: if it's an HTTP crawler, use the `HTTPCrawler` class)
* If you have a subclass other than `Command` or `Python` for the task, make sure you understand which meta options need to be set
* Implement the meta options in `meta_opts = {}`
* Implement the task-specific options in `opts = {}`.
* Add an `install_command` for your task. If binaries can be found on GitHub (you can check the repo to make sure), also use `github_handle = '<org>/<repo>'` so it auto-download binaries
* If your task outputs JSON in file, implement the `on_cmd_done(self)` method, parse the JSON and yield proper results
* If your task supports JSON lines, add an `item_loaders = [JSONSerializer()]` and implement the `on_json_loaded(self, item)` method
* If your task only supports plaintext output, implement the `on_line(self, line)` and do custom parsing. If it can be a simple regex, use the `item_loaders = [RegexSerializer(regex, fields=[...])]` and then implement the `on_json_loaded(self, item)` method.

### Python
If you want to implement a new Python task (a task that will call custom Python code to achieve the purpose), just implement it (check `secator/tasks/urlparser.py` or `secator/tasks/prompt.py` task for examples).
If you need libraries that are not in `pyproject.toml`, add a new addon to `pyproject.toml` with the libraries you need instead of adding them to the core dependencies.
Make sure to import libraries that are optional within the task methods themselves, not at the top-level. Check how addons are added and add your own (it should have the task name and be installable with `secator install addons <your_addon>`).

## Adding new Secator workflows

When creating new Secator workflows:
* Read all the other workflow YAMLs in `secator/configs/workflows/` to understand how we create workflows.
* If you need tasks not currently supported by secator, follow the "Adding new tasks" section to implement them before you implement the workflow.
* Always add a description, a long description, a type, a name, and tags to the workflow YAML.
