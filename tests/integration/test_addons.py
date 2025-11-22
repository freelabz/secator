import os
import unittest
from unittest import mock


class TestAddonMongoDBConfig(unittest.TestCase):
	"""Test MongoDB addon configuration"""

	@mock.patch.dict(os.environ, {"SECATOR_ADDONS_MONGODB_URL": "mongodb://testhost:27017"})
	def test_mongodb_config_from_env(self):
		"""Test that MongoDB configuration can be set from environment variables"""
		from secator.utils_test import clear_modules
		clear_modules()
		from secator.config import CONFIG

		# Verify the MongoDB URL is set correctly
		self.assertEqual(CONFIG.addons.mongodb.url, "mongodb://testhost:27017")

	@mock.patch.dict(os.environ, {
		"SECATOR_ADDONS_MONGODB_URL": "mongodb://testuser:testpass@testhost:27017",
		"SECATOR_ADDONS_MONGODB_UPDATE_FREQUENCY": "10",
		"SECATOR_ADDONS_MONGODB_SERVER_SELECTION_TIMEOUT_MS": "5000",
		"SECATOR_ADDONS_MONGODB_MAX_POOL_SIZE": "50"
	})
	def test_mongodb_config_all_options(self):
		"""Test that all MongoDB configuration options can be set from environment"""
		from secator.utils_test import clear_modules
		clear_modules()
		from secator.config import CONFIG

		# Verify all MongoDB configuration options
		self.assertEqual(CONFIG.addons.mongodb.url, "mongodb://testuser:testpass@testhost:27017")
		self.assertEqual(CONFIG.addons.mongodb.update_frequency, 10)
		self.assertEqual(CONFIG.addons.mongodb.server_selection_timeout_ms, 5000)
		self.assertEqual(CONFIG.addons.mongodb.max_pool_size, 50)
