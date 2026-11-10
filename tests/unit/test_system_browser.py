import unittest
from unittest import mock

from secator.tasks import httpx, katana
from secator.utils import SYSTEM_BROWSERS, find_system_browser

CHROMIUM = '/usr/bin/chromium'


def which(found=None):
	return lambda name: found if name == 'chromium' and found else None


class TestFindSystemBrowser(unittest.TestCase):

	def test_found(self):
		with mock.patch('secator.utils.shutil.which', side_effect=which(CHROMIUM)):
			self.assertEqual(find_system_browser(), CHROMIUM)

	def test_not_found(self):
		with mock.patch('secator.utils.shutil.which', return_value=None) as m:
			self.assertIsNone(find_system_browser())
		self.assertEqual([c.args[0] for c in m.call_args_list], list(SYSTEM_BROWSERS))

	def test_lookup_order(self):
		with mock.patch('secator.utils.shutil.which', side_effect=lambda name: f'/bin/{name}'):
			self.assertEqual(find_system_browser(), '/bin/chrome')


class TestSystemBrowserDecision(unittest.TestCase):

	def _build(self, cls, browser=None, musl=False, installed=True, **opts):
		with mock.patch('secator.utils.shutil.which', side_effect=which(browser)), \
			mock.patch('secator.tasks._categories.glob.glob', return_value=['/lib/ld-musl-x86_64.so.1'] if musl else []), \
			mock.patch.object(cls, 'is_installed', return_value=installed):
			task = cls('http://example.com', sync=True, print_cmd=False, run=False, **opts)
		warnings = [r for r in task.results if r._type == 'warning']
		return task.cmd.count('-system-chrome'), warnings

	def test_unset_browser_found(self):
		self.assertEqual(self._build(httpx, CHROMIUM, screenshot=True), (1, []))
		self.assertEqual(self._build(katana, CHROMIUM, headless=True), (1, []))

	def test_unset_browser_not_found_downloads(self):
		self.assertEqual(self._build(httpx, screenshot=True), (0, []))
		self.assertEqual(self._build(katana, headless=True), (0, []))

	def test_browser_not_used(self):
		self.assertEqual(self._build(httpx, CHROMIUM), (0, []))
		self.assertEqual(self._build(katana, CHROMIUM), (0, []))

	def test_explicit_true(self):
		self.assertEqual(self._build(katana, CHROMIUM, headless=True, system_chrome=True), (1, []))

	def test_explicit_true_not_found_warns(self):
		count, warnings = self._build(katana, headless=True, system_chrome=True)
		self.assertEqual(count, 1)
		self.assertEqual(len(warnings), 1)
		self.assertIn('system_chrome is set', warnings[0].message)

	def test_explicit_false(self):
		self.assertEqual(self._build(httpx, CHROMIUM, screenshot=True, system_chrome=False), (0, []))

	def test_downloads_disabled(self):
		for offline, auto_install in [(True, True), (False, False)]:
			with self.subTest(offline=offline, auto_install=auto_install), \
				mock.patch('secator.tasks._categories.CONFIG') as config:
				config.offline_mode = offline
				config.security.auto_install_commands = auto_install
				self.assertEqual(self._build(httpx, CHROMIUM, screenshot=True, system_chrome=False), (1, []))
				count, warnings = self._build(katana, headless=True)
				self.assertEqual(count, 1)
				self.assertIn('browser downloads are disabled', warnings[0].message)

	def test_musl_never_downloads(self):
		self.assertEqual(self._build(katana, headless=True, musl=True, installed=False), (1, []))
		self.assertEqual(self._build(katana, CHROMIUM, headless=True, musl=True), (1, []))
