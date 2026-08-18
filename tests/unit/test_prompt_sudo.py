import types
import unittest
from unittest.mock import patch

from secator.config import CONFIG
from secator.runners.command import Command


class TestPromptSudo(unittest.TestCase):
	"""_prompt_sudo must never crash the task on a missing/broken TTY (issue #1332)."""

	def _stub(self, has_tty=True):
		# _prompt_sudo only touches these attributes — avoid a full Command __init__.
		return types.SimpleNamespace(has_tty=has_tty, _print=lambda *a, **k: None)

	@patch('subprocess.run', return_value=types.SimpleNamespace(returncode=1))
	@patch('getpass.getuser', return_value='test')
	@patch('getpass.getpass', side_effect=ValueError('I/O operation on closed file'))
	def test_getpass_failure_degrades_gracefully(self, *_):
		stub = self._stub(has_tty=True)  # heuristic says TTY, but stdin is actually broken
		password, error = Command._prompt_sudo(stub, 'sudo masscan')
		self.assertEqual(password, -1)  # -1 + non-empty error => caller yields Error and returns
		self.assertTrue(error)

	@patch('subprocess.run', return_value=types.SimpleNamespace(returncode=1))
	def test_no_tty_returns_error(self, _):
		stub = self._stub(has_tty=False)
		password, error = Command._prompt_sudo(stub, 'sudo masscan')
		self.assertEqual(password, -1)
		self.assertTrue(error)

	def test_no_sudo_is_noop(self):
		stub = self._stub()
		self.assertEqual(Command._prompt_sudo(stub, 'nmap -sT target'), (None, []))

	@patch('getpass.getpass', side_effect=AssertionError('must not prompt when password configured'))
	def test_configured_password_used_without_tty(self, _):
		stub = self._stub(has_tty=False)  # headless worker: no prompt possible
		# sudo -n true => needs password (rc 1); sudo -S with the configured password => ok (rc 0)
		runs = [types.SimpleNamespace(returncode=1), types.SimpleNamespace(returncode=0)]
		with patch.object(CONFIG.security, 'sudo_password', 'hunter2'):
			with patch('subprocess.run', side_effect=runs):
				password, error = Command._prompt_sudo(stub, 'sudo masscan')
		self.assertEqual(password, 'hunter2')
		self.assertIsNone(error)

	def test_configured_password_wrong(self):
		stub = self._stub(has_tty=False)
		runs = [types.SimpleNamespace(returncode=1), types.SimpleNamespace(returncode=1)]
		with patch.object(CONFIG.security, 'sudo_password', 'wrong'):
			with patch('subprocess.run', side_effect=runs):
				password, error = Command._prompt_sudo(stub, 'sudo masscan')
		self.assertEqual(password, -1)
		self.assertTrue(error)


if __name__ == '__main__':
	unittest.main()
