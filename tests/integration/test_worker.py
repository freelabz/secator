import unittest
from secator.runners import Command
from time import sleep
from threading import Thread
import queue


class TestWorker(unittest.TestCase):
	def setUp(self):
		self.queue = queue.Queue()
		self.cmd = Command.execute('secator worker', delay_run=True)
		self.thread = Thread(target=self.cmd.run)
		self.thread.start()
		sleep(3)

	def tearDown(self) -> None:
		self.cmd.process.kill()
		self.thread.join()

	def test_httpx(self):
		cmd = Command.execute('secator x httpx testphp.vulnweb.com -json')
		self.assertEqual(cmd.return_code, 0)
		self.assertGreater(len(cmd.results), 0)

	def test_host_recon(self):
		cmd = Command.execute('secator w host_recon vulnweb.com -json')
		self.assertEqual(cmd.return_code, 0)
		self.assertGreater(len(cmd.results), 0)
