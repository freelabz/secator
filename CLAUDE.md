# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Secator is a Python-based security assessment automation framework ("the pentester's swiss knife") that integrates 40+ security tools into a unified CLI. It provides standardized input/output across tools, workflow composition via YAML, and distributed execution via Celery or Airflow.

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

## Linting

Flake8 config (`.flake8`): max-line-length=120, ignores W191, E101, E128, E265, W605
