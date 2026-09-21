import subprocess
import sys
import time
import unittest

import psutil

from secator.runners import Command


# Prints a flushed readiness marker BEFORE spinning, so the test can wait for the
# child to actually be burning CPU. Popen returns as soon as the fork succeeds,
# and interpreter startup can easily exceed the sampling window -- sampling before
# the loop starts reads ~0% and fails a correct implementation.
BUSY = (
	'import sys, time\n'
	'sys.stdout.write("READY\\n")\n'
	'sys.stdout.flush()\n'
	't = time.time()\n'
	'while time.time() - t < 5:\n'
	'\tpass\n'
)

# Spawns CHILDREN that also spin, to exercise the batched (prime-all / sleep-once /
# read-all) path and prove the wall-clock cost does not scale with process count.
BUSY_TREE = (
	'import subprocess, sys, time\n'
	'kids = [subprocess.Popen([sys.executable, "-c",\n'
	'	"import time\\nt=time.time()\\nwhile time.time()-t < 5: pass"]) for _ in range(3)]\n'
	'sys.stdout.write("READY\\n")\n'
	'sys.stdout.flush()\n'
	't = time.time()\n'
	'while time.time() - t < 5:\n'
	'\tpass\n'
)


def _spawn(src):
	proc = subprocess.Popen([sys.executable, '-c', src], stdout=subprocess.PIPE, text=True)
	assert proc.stdout.readline().strip() == 'READY', 'child never signalled readiness'
	return proc


class TestGetProcessInfoCpu(unittest.TestCase):

	def test_cpu_percent_nonzero_on_first_sample(self):
		"""A fresh psutil.Process must still report real CPU.

		Regression: as_dict()'s cpu_percent is psutil's FIRST call on that object, which
		is always 0.0 by definition. Every Stat.cpu in prod was 0 because of this.
		"""
		proc = _spawn(BUSY)
		try:
			# fresh Process object, exactly like _collect_stats() builds on every monitor tick
			info = next(Command.get_process_info(psutil.Process(proc.pid)))
			self.assertGreater(info['cpu_percent'], 1.0)
		finally:
			proc.kill()
			proc.wait()

	def test_cpu_sampling_is_batched_across_children(self):
		"""Sampling a tree must cost ONE wait, not one per process.

		_monitor_process() materializes this generator before it checks the memory limit,
		so a per-process blocking interval would delay that guard by N * the window.
		"""
		proc = _spawn(BUSY_TREE)
		try:
			start = time.monotonic()
			infos = list(Command.get_process_info(psutil.Process(proc.pid), children=True))
			elapsed = time.monotonic() - start

			self.assertGreaterEqual(len(infos), 4, 'expected parent + 3 children')
			# One window plus overhead -- and well under the N-per-process cost.
			budget = Command.CPU_SAMPLE_SECONDS * len(infos)
			self.assertLess(elapsed, budget, f'{elapsed:.2f}s looks serial, not batched (N={len(infos)})')
			self.assertGreater(max(i['cpu_percent'] for i in infos), 1.0)
		finally:
			for child in psutil.Process(proc.pid).children(recursive=True):
				try:
					child.kill()
				except psutil.Error:
					pass
			proc.kill()
			proc.wait()


if __name__ == '__main__':
	unittest.main()
