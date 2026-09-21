import subprocess
import sys
import unittest

import psutil

from secator.runners import Command


BUSY = 'import time\nt = time.time()\nwhile time.time() - t < 5:\n\tpass\n'


class TestGetProcessInfoCpu(unittest.TestCase):

	def test_cpu_percent_nonzero_on_first_sample(self):
		"""A fresh psutil.Process must still report real CPU (issue: as_dict's cpu_percent is always 0.0)."""
		proc = subprocess.Popen([sys.executable, '-c', BUSY])
		try:
			# fresh Process object, exactly like _collect_stats() builds on every monitor tick
			info = next(Command.get_process_info(psutil.Process(proc.pid)))
			self.assertGreater(info['cpu_percent'], 1.0)
		finally:
			proc.kill()
			proc.wait()
