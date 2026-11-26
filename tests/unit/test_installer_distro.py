import os
import unittest
from unittest import mock

from secator.installer import Distribution, get_distro_config


class TestGetDistroConfig(unittest.TestCase):

	def _get(self, env, system='Linux', distrib='debian'):
		with mock.patch.dict('os.environ', env, clear=False), \
				mock.patch('secator.installer.platform.system', return_value=system), \
				mock.patch('secator.installer.distro.like', return_value=distrib), \
				mock.patch('secator.installer.distro.id', return_value=distrib):
			return get_distro_config()

	def test_detected(self):
		env = {k: v for k, v in os.environ.items() if k != 'SECATOR_PACKAGE_MANAGER'}
		with mock.patch.dict('os.environ', env, clear=True):
			dist = self._get({})
		self.assertIsInstance(dist, Distribution)
		self.assertEqual(dist.name, 'debian')
		self.assertEqual(dist.pm_name, 'apt')
		self.assertEqual(dist.pm_finalizer, 'rm -rf /var/lib/apt/lists/*')

	def test_override_known_name(self):
		dist = self._get({'SECATOR_PACKAGE_MANAGER': 'apk'})
		self.assertIsInstance(dist, Distribution)
		self.assertEqual(dist.name, 'debian')
		self.assertEqual(dist.system, 'Linux')
		self.assertEqual(dist.pm_name, 'apk')
		self.assertEqual(dist.pm_installer, 'apk add --no-cache')
		self.assertIsNone(dist.pm_finalizer)

	def test_override_full_command(self):
		dist = self._get({'SECATOR_PACKAGE_MANAGER': 'apt-get install -y'})
		self.assertIsInstance(dist, Distribution)
		self.assertEqual(dist.pm_name, 'apt-get')
		self.assertEqual(dist.pm_installer, 'apt-get install -y')
		self.assertIsNone(dist.pm_finalizer)

	def test_override_on_unknown_distribution(self):
		dist = self._get({'SECATOR_PACKAGE_MANAGER': 'dnf'}, distrib='unknownlinux')
		self.assertEqual(dist.pm_name, 'dnf')
		self.assertEqual(dist.pm_installer, 'dnf install -y')
		self.assertEqual(dist.pm_finalizer, 'dnf clean all')


if __name__ == '__main__':
	unittest.main()
