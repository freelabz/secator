import os
import signal
from unittest.mock import MagicMock


def test_command_supports_pause_default():
	from secator.runners.command import Command
	assert Command.supports_pause is True


def test_pause_process_sigint(monkeypatch):
	from secator.runners.command import Command
	cmd = Command.__new__(Command)
	mock_process = MagicMock()
	mock_process.pid = 99999
	cmd.process = mock_process
	cmd.paused = False
	cmd.pause_method = None

	stopped_with = []

	def mock_stop_process(exit_ok=False, sig=signal.SIGINT):
		stopped_with.append(sig)

	cmd.stop_process = mock_stop_process
	cmd.pause_process()

	assert signal.SIGINT in stopped_with
	assert cmd.paused is True
	assert cmd.pause_method == 'kill'


def test_pause_process_kill_fallback():
	from secator.runners.command import Command
	cmd = Command.__new__(Command)
	mock_process = MagicMock()
	mock_process.pid = 99999
	cmd.process = mock_process
	cmd.paused = False
	cmd.pause_method = None
	cmd.completed_inputs = ['10.0.0.1']

	def mock_stop_process_raises(exit_ok=False, sig=signal.SIGINT):
		raise OSError('permission denied')

	cmd.stop_process = mock_stop_process_raises
	cmd.pause_process()

	mock_process.terminate.assert_called_once()
	assert cmd.paused is True
	assert cmd.pause_method == 'kill'


def test_resume_process_sigcont(monkeypatch):
	from secator.runners.command import Command
	cmd = Command.__new__(Command)
	cmd.pause_method = 'signal'
	mock_process = MagicMock()
	mock_process.pid = 99999
	cmd.process = mock_process
	cmd.paused = True

	killed = []
	monkeypatch.setattr(os, 'kill', lambda pid, sig: killed.append((pid, sig)))
	cmd.resume_process()

	assert (99999, signal.SIGCONT) in killed
	assert cmd.paused is False
