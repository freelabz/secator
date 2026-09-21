import subprocess
import sys
import time
import unittest

import psutil

from secator.runners import Command


# Flushed readiness marker before spinning: Popen returns as soon as the fork
# succeeds, and interpreter startup can outlast the interval we measure over.
BUSY = (
	'import sys, time\n'
	'sys.stdout.write("READY\\n")\n'
	'sys.stdout.flush()\n'
	't = time.time()\n'
	'while time.time() - t < 6:\n'
	'\tpass\n'
)


def _spawn():
	proc = subprocess.Popen([sys.executable, '-c', BUSY], stdout=subprocess.PIPE, text=True)
	assert proc.stdout.readline().strip() == 'READY', 'child never signalled readiness'
	return proc


class TestGetProcessInfoCpu(unittest.TestCase):
	"""Regression: as_dict()'s cpu_percent is psutil's FIRST call on that object, which is
	always 0.0. Every Stat.cpu in prod was 0 because a fresh Process was built per tick."""

	def test_reusing_processes_reports_real_cpu(self):
		proc = _spawn()
		procs = {}
		try:
			next(Command.get_process_info(psutil.Process(proc.pid), procs=procs))  # baseline
			time.sleep(Command.first_stat_delay)
			info = next(Command.get_process_info(psutil.Process(proc.pid), procs=procs))
			self.assertGreater(info['cpu_percent'], 1.0)
		finally:
			proc.kill()
			proc.wait()

	def test_without_procs_cpu_is_always_zero(self):
		"""Shows the bug directly: no reuse means every read is a first call."""
		proc = _spawn()
		try:
			next(Command.get_process_info(psutil.Process(proc.pid)))
			time.sleep(Command.first_stat_delay)
			info = next(Command.get_process_info(psutil.Process(proc.pid)))
			self.assertEqual(info['cpu_percent'], 0.0)
		finally:
			proc.kill()
			proc.wait()

	def test_collection_does_not_block(self):
		"""It reads a counter; it must not watch the process."""
		proc = _spawn()
		procs = {}
		try:
			next(Command.get_process_info(psutil.Process(proc.pid), procs=procs))
			start = time.monotonic()
			list(Command.get_process_info(psutil.Process(proc.pid), children=True, procs=procs))
			self.assertLess(time.monotonic() - start, 0.05)
		finally:
			proc.kill()
			proc.wait()

	def test_same_process_object_is_reused(self):
		"""The baseline lives on the object, so swapping it silently restores the bug."""
		proc = _spawn()
		procs = {}
		try:
			next(Command.get_process_info(psutil.Process(proc.pid), procs=procs))
			first = procs[proc.pid]
			next(Command.get_process_info(psutil.Process(proc.pid), procs=procs))
			self.assertIs(procs[proc.pid], first)
		finally:
			proc.kill()
			proc.wait()

	def test_first_stat_delay_is_measurable_but_short(self):
		"""Long enough to beat the 10ms clock granularity, short enough that few tasks
		exit before the first tick (prod: 18% finish under 1s, 5% under 0.3s)."""
		self.assertGreaterEqual(Command.first_stat_delay, 0.1)
		self.assertLess(Command.first_stat_delay, 1.0)


if __name__ == '__main__':
	unittest.main()
