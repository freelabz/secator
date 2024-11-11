import os
import unittest
from unittest import mock
from secator.utils_test import clear_modules
from secator.config import CONFIG


class TestAddonMongo(unittest.TestCase):

	@classmethod
	@mock.patch.dict(os.environ, {"SECATOR_ADDONS_MONGODB_URL": "mongodb://localhost"})
	def setUpClass(cls):
		clear_modules()
		from secator.config import CONFIG
		print(CONFIG.addons.mongodb.url)
		raise Exception('test')

	@classmethod
	def tearDownClass(cls):
		pass

	def test_ok(self):
		print(CONFIG.addons.mongodb.url)