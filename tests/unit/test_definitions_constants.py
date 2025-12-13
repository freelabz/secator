import unittest

from secator.definitions import AVAILABLE_DRIVERS, AVAILABLE_EXPORTERS
from secator.completion import AVAILABLE_DRIVERS as COMP_DRIVERS, AVAILABLE_EXPORTERS as COMP_EXPORTERS
from secator.cli_helper import DRIVERS_STR, EXPORTERS_STR


class TestDefinitionsConstants(unittest.TestCase):
	"""Test that drivers and exporters are defined in a single location."""

	def test_available_drivers_defined(self):
		"""Test that AVAILABLE_DRIVERS is properly defined."""
		self.assertIsInstance(AVAILABLE_DRIVERS, list)
		self.assertGreater(len(AVAILABLE_DRIVERS), 0)
		# Verify expected drivers are present
		self.assertIn('mongodb', AVAILABLE_DRIVERS)
		self.assertIn('gcs', AVAILABLE_DRIVERS)

	def test_available_exporters_defined(self):
		"""Test that AVAILABLE_EXPORTERS is properly defined."""
		self.assertIsInstance(AVAILABLE_EXPORTERS, list)
		self.assertGreater(len(AVAILABLE_EXPORTERS), 0)
		# Verify expected exporters are present
		self.assertIn('csv', AVAILABLE_EXPORTERS)
		self.assertIn('json', AVAILABLE_EXPORTERS)
		self.assertIn('table', AVAILABLE_EXPORTERS)

	def test_completion_imports_from_definitions(self):
		"""Test that completion module imports from definitions."""
		# Verify they reference the same object
		self.assertIs(COMP_DRIVERS, AVAILABLE_DRIVERS)
		self.assertIs(COMP_EXPORTERS, AVAILABLE_EXPORTERS)

	def test_cli_helper_uses_constants(self):
		"""Test that cli_helper uses the constants properly."""
		# DRIVERS_STR and EXPORTERS_STR should contain all drivers/exporters
		for driver in AVAILABLE_DRIVERS:
			self.assertIn(driver, DRIVERS_STR)
		for exporter in AVAILABLE_EXPORTERS:
			self.assertIn(exporter, EXPORTERS_STR)


if __name__ == '__main__':
	unittest.main()
