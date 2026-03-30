import os
import signal
import pytest
from unittest.mock import MagicMock, patch


def test_command_supports_pause_default():
	from secator.runners.command import Command
	assert Command.supports_pause is True


def test_pause_process_sigstop(monkeypatch):
	from secator.runners.command import Command
	cmd = Command.__new__(Command)
	cmd.supports_pause = True
	mock_process = MagicMock()
	mock_process.pid = 99999
	cmd.process = mock_process
	cmd.paused = False
	cmd.pause_method = None

	killed = []
	monkeypatch.setattr(os, 'kill', lambda pid, sig: killed.append((pid, sig)))
	cmd.pause_process()

	assert (99999, signal.SIGSTOP) in killed
	assert cmd.paused is True
	assert cmd.pause_method == 'signal'


def test_pause_process_kill_fallback():
	from secator.runners.command import Command
	cmd = Command.__new__(Command)
	cmd.supports_pause = False
	mock_process = MagicMock()
	mock_process.pid = 99999
	cmd.process = mock_process
	cmd.paused = False
	cmd.pause_method = None
	cmd.completed_inputs = ['10.0.0.1']

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
