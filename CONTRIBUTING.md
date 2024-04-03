
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

## Other code

- Make sure you pass the `lint` and `unit` tests:
	- `secator test unit`
	- `secator test lint`
- Open a new pull request with your changes.