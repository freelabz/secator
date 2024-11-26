import os
from unittest import mock
from secator.utils_test import clear_modules, SecatorTestCase
from secator.config import CONFIG


class TestAddonMongo(SecatorTestCase):

	@classmethod
	@mock.patch.dict(os.environ, {"SECATOR_ADDONS_MONGODB_URL": "mongodb://localhost:27018"})
	def setUpClass(cls):
		clear_modules()
		from secator.config import CONFIG
		super().setUpClass()

	def test_ok(self):
		print(CONFIG.addons.mongodb.url)