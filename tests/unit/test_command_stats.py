import subprocess
import sys
import time
import unittest

import psutil

from secator.runners import Command


# Readiness marker: Popen returns before the interpreter reaches the loop.
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
	"""Regression: a fresh psutil.Process per tick made every cpu read a first call (0.0)."""

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
		"""The bug itself: no reuse, every read is a first call."""
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
		"""It reads a counter, it does not watch the process."""
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
		"""The baseline lives on the object; swapping it silently restores the bug."""
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
		"""Long enough to beat clock granularity, short enough that few tasks exit first."""
		self.assertGreaterEqual(Command.first_stat_delay, 0.1)
		self.assertLess(Command.first_stat_delay, 1.0)


if __name__ == '__main__':
	unittest.main()
