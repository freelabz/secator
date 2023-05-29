
Please read this document before opening a new pull request.

## Contribute a new task

To contribute a new task back to `secsy` repository, it needs to validate some requirements:

- Verify your **task class definition**:
  - It MUST have an `input_type` key.
  - It MUST have an `output_types` key.
  - It MUST have an `install_cmd` key.

- Add your **task definition** to the `tasks/` directory. If your task class is named `MyAwesomeTask`, call it `my_awesome_task.py`
- [Optional] Add your output type to `secsy`:
	- Add your type definition to `output_types/` directory. If your output type is named `MyAwesomeType`, call it `my_awesome_type.py`
	- Import your type class in `__init__.py`

- Add a **unit test** for your task:
	- `tests/fixtures/<MYTASK>_output.(json|xml|rc|txt)`: add a fixture for the original command output.
		- Make sure it is anonymized from PII data
		- Run `secsy x mytask <HOST>` to make sure the output is shown correctly on the CLI. Also run with `-json` to 
			verify the output schema
		- This fixture will be used by unit tests to emulate data sent by your task
	- Validate your unit test by running: `secsy test unit --task <MYTASK> --test test_tasks`

- Add an **integration test** for your task:
	- `tests/integration/inputs.py` - to modify integration inputs
	- `tests/integration/outputs.py` - to modify expected outputs
	- Validate your integration test by running: `secsy test integration --task <MYTASK> --test test_tasks`

- Run the lint tests: `secsy test lint`

- Once `unit`, `integration` and `lint` tests pass:
	- Generate the new command installation with `secsy u generate-bash-install`
	- Add the updated `scripts/install_commands.sh` to your commit.

- Open a new pull request with your changes.

### New workflow / scan

- Add your workflow / scan YAML definition `awesome_work.yml` to `configs/workflows/`

- Make sure the `name` YAML key is the same as your workflow's file name.

- Make sure the `type` YAML key is set to `workflow` or `scan`.

- Add some integration tests:
	- `inputs.py`: add inputs for your workflow
	- `outputs.py`: add some expected outputs of your workflow

- Run the integration tests:
	- For workflows: `secsy test integration --test test_workflows --workflows <MYWORKFLOW>
	- For scans: `secsy test integration --test test_scans --scans <MYSCAN>`

- Open a new pull request with your changes.

## Other code

- Make sure you pass the `lint` and `unit` tests:
	- `secsy test unit`
	- `secsy test lint`
- Open a new pull request with your changes.