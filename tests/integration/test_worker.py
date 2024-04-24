import unittest
from secator.runners import Command

class TestWorker(unittest.TestCase):
	def setUp(self):
		self.cmd = Command.execute('secator worker')

	def tearDown(self) -> None:
		self.cmd.process.kill()