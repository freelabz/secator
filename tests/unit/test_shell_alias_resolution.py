"""Command resolves tools that exist only as a shell alias (e.g. Exegol/RVM),
which PATH lookups (which / shutil.which) can't see, and runs them instead of
installing a conflicting copy.

Regression context: Exegol exposes wpscan as an RVM-gemset alias, not a PATH
binary — `which wpscan` failed in secator's non-interactive subprocess, so
secator auto-installed its own (broken) copy that shadowed the working one.
"""
import unittest
from unittest.mock import MagicMock, patch

from secator.runners.command import Command


def _type_output(stdout):
	return MagicMock(stdout=stdout, returncode=0)


class TestShellAliasResolution(unittest.TestCase):

	def test_resolve_bash_alias_format(self):
		# bash `alias`: "alias name='<expansion>'"
		with patch.dict('os.environ', {'SHELL': '/bin/bash'}), \
			 patch('secator.runners.command.subprocess.run',
				   return_value=_type_output("alias wpscan='/rvm/wrappers/ruby /rvm/bin/wpscan'")):
			self.assertEqual(
				Command._resolve_shell_alias('wpscan'),
				'/rvm/wrappers/ruby /rvm/bin/wpscan')

	def test_resolve_zsh_alias_format(self):
		# zsh `alias`: "name='<expansion>'" (no leading 'alias ')
		with patch.dict('os.environ', {'SHELL': '/usr/bin/zsh'}), \
			 patch('secator.runners.command.subprocess.run',
				   return_value=_type_output("wpscan='/rvm/bin/wpscan'")):
			self.assertEqual(Command._resolve_shell_alias('wpscan'), '/rvm/bin/wpscan')

	def test_not_an_alias_returns_none(self):
		# genuinely-missing / non-alias -> `alias` prints nothing -> None
		with patch.dict('os.environ', {'SHELL': '/bin/bash'}), \
			 patch('secator.runners.command.subprocess.run', return_value=_type_output("")):
			self.assertIsNone(Command._resolve_shell_alias('wpscan'))

	def test_no_shell_returns_none_without_spawning(self):
		with patch.dict('os.environ', {'SHELL': ''}), \
			 patch('secator.runners.command.subprocess.run', side_effect=AssertionError('should not run')):
			self.assertIsNone(Command._resolve_shell_alias('wpscan'))

	def test_shell_error_returns_none(self):
		with patch.dict('os.environ', {'SHELL': '/bin/bash'}), \
			 patch('secator.runners.command.subprocess.run', side_effect=OSError('boom')):
			self.assertIsNone(Command._resolve_shell_alias('wpscan'))

	def test_splice_preserves_sudo_prefix(self):
		c = Command.__new__(Command)
		c.cmd_name = 'wpscan'
		c.cmd = 'sudo wpscan --force --url http://x'
		c._splice_resolved_command('/rvm/ruby /rvm/bin/wpscan')
		self.assertEqual(c.cmd, 'sudo /rvm/ruby /rvm/bin/wpscan --force --url http://x')

	def test_splice_first_token_only_and_word_boundary(self):
		c = Command.__new__(Command)
		c.cmd_name = 'nmap'
		# 'nmap' is also a substring of a path arg — only the standalone token is replaced
		c.cmd = 'nmap -oX /tmp/nmap_scan.xml target'
		c._splice_resolved_command('/opt/nmap')
		self.assertEqual(c.cmd, '/opt/nmap -oX /tmp/nmap_scan.xml target')

	def test_is_installed_is_path_only(self):
		c = Command.__new__(Command)
		c.cmd_name = 'definitely-not-a-real-binary-xyz-123'
		self.assertFalse(c.is_installed())


if __name__ == '__main__':
	unittest.main()
