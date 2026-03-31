from unittest.mock import MagicMock, patch


def test_workflow_checkpoint_task_states():
	from secator.runners.checkpoint import Checkpoint
	cp = Checkpoint(
		runner_type='workflow',
		runner_id='wf-abc',
		runner_name='host_recon',
		targets=['10.0.0.1'],
		opts={},
		context={'workflow_id': 'wf-abc'},
		task_states={'nmap': 'completed', 'httpx': 'pending'},
		completed_results_count=5,
	)
	completed = [n for n, s in cp.task_states.items() if s == 'completed']
	pending = [n for n, s in cp.task_states.items() if s != 'completed']
	assert completed == ['nmap']
	assert pending == ['httpx']
