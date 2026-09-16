"""bbot's native deps (regex, yara-python) have no prebuilt wheels on newer
Pythons (e.g. 3.14), so pip builds them from source and needs the Python dev
headers. The apt/dnf install prereqs must therefore carry python3-dev /
python3-devel — otherwise `secator install bbot` fails on Ubuntu/Debian with
`fatal error: Python.h: No such file or directory`.
"""
import unittest

from secator.tasks.bbot import bbot


def _resolve(install_pre, pm_name):
	"""Mirror PackageInstaller's first-match resolution (managers split on '|',
	'*' is the catch-all)."""
	for managers, packages in install_pre.items():
		if pm_name in managers.split('|') or managers == '*':
			return packages
	return []


class TestBbotInstall(unittest.TestCase):

	def test_apt_prereqs_include_python_headers(self):
		pkgs = _resolve(bbot.install_pre, 'apt')  # ubuntu / debian / kali
		self.assertIn('python3-dev', pkgs)
		self.assertIn('gcc', pkgs)

	def test_dnf_yum_prereqs_include_python_headers(self):
		for pm in ('dnf', 'yum', 'zypper'):
			self.assertIn('python3-devel', _resolve(bbot.install_pre, pm), pm)

	def test_apk_prereqs_still_have_headers(self):
		self.assertIn('python3-dev', _resolve(bbot.install_pre, 'apk'))

	def test_install_post_cleanup_is_python_version_agnostic(self):
		post = bbot.install_post['*']
		self.assertIn('python3.*', post)
		self.assertNotIn('python3.12', post)


if __name__ == '__main__':
	unittest.main()
