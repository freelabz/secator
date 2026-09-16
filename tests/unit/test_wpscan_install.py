"""wpscan must install into a fixed gem dir and export GEM_HOME so its generated
`wpscan` wrapper resolves the gem regardless of the host ruby manager.

Regression for #1366: a `--user-install` gem is NOT on RVM's Gem.path (exegol),
so the wrapper crashed with `Gem::GemNotFoundException: can't find gem wpscan`
while the pre-installed system wpscan (an RVM gemset) worked. Installing with
`--install-dir <dir>` and pointing GEM_HOME at <dir> at run time fixes it.
"""
import unittest

from secator.tasks.wpscan import wpscan


class TestWpscanInstall(unittest.TestCase):

	def test_installs_into_fixed_gem_dir_not_user_install(self):
		self.assertIn(f'--install-dir {wpscan.install_gem_dir}', wpscan.install_cmd)
		self.assertNotIn('--user-install', wpscan.install_cmd)

	def test_gem_home_env_points_at_install_dir(self):
		# GEM_HOME is always on Gem.path, so the wrapper finds the gem at run time
		# even when the inherited Gem.path (e.g. RVM on exegol) excludes install_gem_dir.
		self.assertEqual(wpscan.extra_env.get('GEM_HOME'), wpscan.install_gem_dir)

	def test_nokogiri_post_uses_install_dir(self):
		post = wpscan.install_post['kali']
		self.assertIn(f'--install-dir {wpscan.install_gem_dir}', post)
		self.assertNotIn('--user-install', post)


if __name__ == '__main__':
	unittest.main()
