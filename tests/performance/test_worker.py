import unittest
from secator.runners import Command
from secator.config import CONFIG
from time import sleep
from threading import Thread
from secator.celery import is_celery_worker_alive

class TestWorker(unittest.TestCase):

	# @classmethod
	# def setUpClass(cls):
	# 	profiles_folder = CONFIG.dirs.performance
	# 	cls.test_file = f'{profiles_folder}/test.html'
	# 	cmd = f'pyinstrument -r html --from-path secator worker'
	# 	print('Running worker with pyinstrument...')
	# 	print(cmd)
	# 	cls.cmd = Command.execute(cmd, quiet=True, print_cmd=True, run=False)
	# 	cls.thread = Thread(target=cls.cmd.run)
	# 	cls.thread.start()
	# 	sleep(3)

	# @classmethod
	# def tearDownClass(cls) -> None:
	# 	cls.cmd.stop_process()
	# 	cls.thread.join()
	# 	print(f'Profiler output saved to {cls.test_file}')

	def test_httpx(self):
		from secator.tasks import httpx
		result = httpx.delay(['jahmyst.synology.me'], print_line=True, print_cmd=True, print_item=True)
		print(result.get())
