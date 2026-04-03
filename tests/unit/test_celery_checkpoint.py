from unittest.mock import MagicMock, patch


def test_save_celery_checkpoint():
	from secator.celery import save_celery_checkpoint
	from secator.runners.checkpoint import Checkpoint

	cp = Checkpoint(
		runner_type='task',
		runner_id='abc-123',
		runner_name='nmap',
		targets=['10.0.0.1'],
		opts={},
		context={},
	)
	with patch('secator.celery.app') as mock_app:
		mock_app.backend = MagicMock()
		save_celery_checkpoint(cp)
		mock_app.backend.set.assert_called_once()
		call_args = str(mock_app.backend.set.call_args)
		assert 'checkpoint:abc-123' in call_args
