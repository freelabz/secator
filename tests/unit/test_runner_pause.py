from unittest.mock import MagicMock


def test_runner_pause_saves_checkpoint(tmp_path):
	from secator.runners._base import Runner
	from secator.runners.checkpoint import Checkpoint

	runner = MagicMock(spec=Runner)
	runner.paused = False
	runner.config = MagicMock()
	runner.config.type = 'task'
	runner.name = 'nmap'
	runner.inputs = ['10.0.0.1', '10.0.0.2']
	runner.run_opts = {'ports': '80'}
	runner.context = {'task_id': 'abc-123', 'workspace_name': 'default'}
	runner.completed_inputs = ['10.0.0.1']
	runner.reports_folder = str(tmp_path)
	runner.process = None

	Runner.pause(runner)

	cp = Checkpoint.load(tmp_path)
	assert cp is not None
	assert cp.runner_id == 'abc-123'
	assert cp.completed_inputs == ['10.0.0.1']
	assert runner.paused is True
