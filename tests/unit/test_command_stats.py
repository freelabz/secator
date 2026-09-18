import subprocess
import sys
import time
import unittest

import psutil

from secator.runners import Command

BUSY = 'import time\nt=time.time()\nwhile time.time()-t < 5: pass\n'


class TestCommandCpuStats(unittest.TestCase):
	"""Regression guard: per-task CPU stats were always 0 (see fix/cpu-stats-always-zero).

	`psutil.Process.cpu_percent(interval=None)` returns 0.0 on the FIRST call for a given
	Process object, and the monitor thread builds a fresh `psutil.Process` on every tick, so
	`as_dict()['cpu_percent']` was 0 for every sample ever recorded.
	"""

	def test_two_samples_of_a_busy_process_report_cpu(self):
		"""Sampling a real busy process twice must yield a non-zero CPU %."""
		proc = subprocess.Popen([sys.executable, '-c', BUSY])
		try:
			cpu_cache = {}
			psproc = psutil.Process(proc.pid)
			# 1st tick (fresh psutil.Process, as the monitor thread does)
			list(Command.get_process_info(psproc, cpu_cache=cpu_cache))
			time.sleep(0.5)
			# 2nd tick — deliberately a NEW psutil.Process, which is what used to break it
			info = list(Command.get_process_info(psutil.Process(proc.pid), cpu_cache=cpu_cache))[0]
			self.assertGreater(info['cpu_percent'], 1.0, 'busy process reported ~0% CPU')
		finally:
			proc.kill()
			proc.wait()

	def test_first_sample_falls_back_to_lifetime_average(self):
		"""With no previous sample, CPU % is averaged over the process lifetime (short tasks)."""
		now = time.time()
		info = {'pid': 1, 'create_time': now - 10, 'cpu_times': {'user': 4.0, 'system': 1.0}}
		self.assertAlmostEqual(Command.compute_cpu_percent(info), 50.0, delta=1.0)

	def test_no_cpu_time_is_zero(self):
		info = {'pid': 1, 'create_time': time.time() - 10, 'cpu_times': {'user': 0.0, 'system': 0.0}}
		self.assertEqual(Command.compute_cpu_percent(info), 0.0)

	def test_missing_cpu_times_does_not_raise(self):
		self.assertEqual(Command.compute_cpu_percent({'pid': 1}), 0.0)


if __name__ == '__main__':
	unittest.main()
