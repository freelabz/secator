
Please read this document before opening a new pull request.

## Create a dev environment

To create a dev environment, you can either use `pipx` or `virtualenv` + `pip`:

<details>
	<summary>Pipx</summary>

```sh
git clone https://github.com/freelabz/secator
cd secator
pipx install -e .[dev]
```

</details>

<details>
	<summary>Pip</summary>

```sh
git clone https://github.com/freelabz/secator
cd secator
virtualenv .venv
source .venv/bin/activate
pip install -e .[dev]
```

</details>


## Contribute a new task

To contribute a new task back to `secator` repository, it needs to validate some requirements:

- Verify your **task class definition**:
  - It MUST have an `input_type` key.
  - It MUST have an `output_types` key.
  - It MUST have an `install_cmd` key.

- Add your **task definition** to the `tasks/` directory. If your task class is named `MyAwesomeTask`, call it `my_awesome_task.py`

- [Optional] Add your output type(s) to `secator`:
	- Add your type(s) definition(s) to `output_types/` directory. If your output type is named `MyAwesomeType`, call the file `my_awesome_type.py`
	- Import your type class in `__init__.py`

- Add a **unit test** for your task:
	- `tests/fixtures/<TASK_NAME>_output.(json|xml|rc|txt)`: add a fixture for the original command output.
		- Make sure it is anonymized from PII data
		- Run `secator x <TASK_NAME> <HOST>` to make sure the output is shown correctly on the CLI. Also run with `-json` to 
			verify the output schema
		- This fixture will be used by unit tests to emulate data sent by your task
	- Validate your unit test by running: `secator test unit --task <TASK_NAME> --test test_tasks`

- Add an **integration test** for your task:
	- `tests/integration/inputs.py` - to modify integration inputs
	- `tests/integration/outputs.py` - to modify expected outputs
	- Validate your integration test by running: `secator test integration --task <TASK_NAME> --test test_tasks`

- Run the lint tests: `secator test lint`

- Open a new pull request with your changes.

### New workflow / scan

- Add your workflow / scan YAML definition `awesome_work.yml` to `configs/workflows/`

- Make sure the `name` YAML key is the same as your workflow's file name.

- Make sure the `type` YAML key is set to `workflow` or `scan`.

- Add some integration tests:
	- `inputs.py`: add inputs for your workflow
	- `outputs.py`: add some expected outputs of your workflow

- Run the integration tests:
	- For workflows: `secator test integration --test test_workflows --workflows <WORKFLOW_NAME>`
	- For scans: `secator test integration --test test_scans --scans <SCAN_NAME>`

- Open a new pull request with your changes.

## Debugging and Development

### Using Debug Output

Secator provides a powerful debug system to help you troubleshoot and understand what's happening during execution. Debug output is controlled by the `debug` configuration option.

#### Enabling Debug Output

You can enable debug output in three ways:

1. **Via configuration file** (`~/.secator/config.yml`):
   ```yaml
   debug: all
   ```

2. **Via environment variable**:
   ```bash
   export SECATOR_DEBUG=all
   ```

3. **Via command line** (if supported by the command):
   ```bash
   secator config set debug all
   ```

#### Debug Levels

The `debug` field accepts the following values:

- **`all` or `1`**: Enable all debug output (verbose mode)
- **`''` (empty string)**: Disable debug output (default)
- **Comma-separated component names**: Enable debug output for specific components only

#### Available Debug Components

Here are the available debug components you can use:

| Component | Description |
|-----------|-------------|
| `celery` | Celery task execution and queue operations |
| `celery.app` | Celery application initialization |
| `celery.data` | Celery data operations |
| `celery.poll` | Celery polling operations |
| `celery.state` | Celery state management |
| `cli` | CLI operations and argument parsing |
| `config` | Configuration loading and parsing |
| `cve` | CVE lookup and enrichment operations |
| `cve.circl` | CIRCL CVE provider |
| `cve.match` | CVE matching logic |
| `cve.nmap` | Nmap CVE detection |
| `cve.provider` | CVE provider operations |
| `cve.vulners` | Vulners CVE provider |
| `duplicates` | Duplicate detection and filtering |
| `end` | Task completion and cleanup |
| `error` | Error handling and exceptions |
| `extractor` | Output extraction from tools |
| `extractors` | Output extractor operations |
| `hooks` | Hook execution (MongoDB, GCS, etc.) |
| `hooks.gcs` | Google Cloud Storage hooks |
| `hooks.mongodb` | MongoDB hooks |
| `init` | Task and runner initialization |
| `init.options` | Option and argument initialization |
| `installer` | Tool installation operations |
| `item` | Item processing pipeline |
| `item.convert` | Item type conversion |
| `item.duplicate` | Item duplication detection |
| `line.print` | Line output printing |
| `line.process` | Line processing from tool output |
| `monitor` | Resource monitoring |
| `run` | Task execution |
| `start` | Task startup |
| `stats` | Statistics collection and reporting |
| `template` | Template loading and processing |
| `validators` | Input validation operations |

#### Using Debug Components

**Example 1: Debug all Celery operations**
```bash
export SECATOR_DEBUG=celery
secator scan domain example.com
```

**Example 2: Debug multiple specific components**
```yaml
# ~/.secator/config.yml
debug: celery,hooks,cve
```

**Example 3: Debug all CVE-related components using regex patterns**
```bash
# Regex pattern with wildcard (matches cve.match, cve.circl, etc.)
export SECATOR_DEBUG='cve.*'
# Or in config file:
# debug: cve.*

# Matching behavior:
# - With '*': re.match(pattern + '$', component) - regex matching with auto end-anchor
# - Without '*': component.startswith(pattern) - simple prefix matching
```

**Example 4: Debug workflow execution**
```yaml
debug: init,run,end,stats
```

#### Adding Debug Output to Your Code

When developing new features or tasks, you can add debug output using the `debug()` function:

```python
from secator.utils import debug

# Simple debug message with a component
debug('Task started', sub='mytask')

# Debug with object/data
debug('Processing item', sub='mytask', obj={'url': 'https://example.com'})

# Debug with custom formatting
debug('Found 10 results', sub='mytask.results', obj=['item1', 'item2'])
```

The `debug()` function parameters:
- `msg` (str): The debug message
- `sub` (str): The debug component/subsystem name (used for filtering)
- `obj` (any): Optional object to display (dict, list, etc.)
- `id` (str): Optional identifier to append to the message
- `obj_after` (bool): Whether to show object after the message (default: True)
- `obj_breaklines` (bool): Whether to break lines for each item in object
- `lazy` (callable): Function that takes `msg` as parameter and returns modified message string (for expensive operations)

#### Best Practices for Debug Output

1. **Use meaningful component names**: Choose component names that clearly indicate which part of the code is generating the output
2. **Use hierarchy**: Use dot notation for sub-components (e.g., `cve.match`, `hooks.mongodb`)
3. **Be consistent**: Use the same component names throughout related code
4. **Avoid sensitive data**: Never log sensitive information like passwords, tokens, or PII
5. **Use lazy evaluation**: For expensive operations, use the `lazy` parameter to modify the message:
   ```python
   # lazy takes the message as parameter and returns modified message
   debug('Results', sub='task', lazy=lambda msg: f"{msg}: {expensive_operation()}")
   ```

#### Debugging Common Scenarios

**Debugging Task Execution Issues:**
```bash
export SECATOR_DEBUG=init,start,run,end,error
secator x nmap 192.168.1.1
```

**Debugging Celery/Worker Issues:**
```bash
export SECATOR_DEBUG=celery
secator worker
```

**Debugging Output Parsing:**
```bash
export SECATOR_DEBUG=line.process,item,extractor
secator x tool input
```

**Debugging Hooks (MongoDB, GCS):**
```bash
export SECATOR_DEBUG=hooks
secator scan domain example.com
```

**Debugging CVE Enrichment:**
```bash
export SECATOR_DEBUG=cve.*
secator x nmap 192.168.1.1
```

### Testing Your Changes

After enabling debug output, you can:
1. Identify bottlenecks and performance issues
2. Trace execution flow through the codebase
3. Verify that data is being processed correctly
4. Troubleshoot integration issues with external services

## Other code

- Make sure you pass the `lint` and `unit` tests:
	- `secator test unit`
	- `secator test lint`
- Open a new pull request with your changes.