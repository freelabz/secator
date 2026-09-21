import subprocess
import sys
import time
import unittest

import psutil

from secator.runners import Command


# Prints a flushed readiness marker BEFORE spinning: Popen returns as soon as the
# fork succeeds, and interpreter startup can outlast the window we measure over.
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

	def test_reused_process_reports_real_cpu(self):
		"""Reusing the psutil.Process across ticks must yield real CPU, with no sleep.

		Regression: a fresh Process per tick makes every read psutil's FIRST call, which
		returns 0.0 by definition. Every Stat.cpu in prod was 0 because of this.
		"""
		proc = _spawn()
		cache = {}
		try:
			# tick 1 primes the baseline (as _start_process does for the real process)
			next(Command.get_process_info(psutil.Process(proc.pid), cache=cache))
			time.sleep(0.3)
			# tick 2 measures the interval since tick 1
			info = next(Command.get_process_info(psutil.Process(proc.pid), cache=cache))
			self.assertGreater(info['cpu_percent'], 1.0)
		finally:
			proc.kill()
			proc.wait()

	def test_sampling_does_not_block(self):
		"""Collection must not sleep: it reads a counter, it does not watch the process."""
		proc = _spawn()
		cache = {}
		try:
			next(Command.get_process_info(psutil.Process(proc.pid), cache=cache))
			start = time.monotonic()
			list(Command.get_process_info(psutil.Process(proc.pid), children=True, cache=cache))
			elapsed = time.monotonic() - start
			# A blocking implementation costs >=0.1s per process. This must be far under.
			self.assertLess(elapsed, 0.05, f'collection blocked for {elapsed:.3f}s')
		finally:
			proc.kill()
			proc.wait()

	def test_cache_reuses_the_same_process_object(self):
		"""The baseline lives on the object, so the cache must hand back the same one."""
		proc = _spawn()
		cache = {}
		try:
			next(Command.get_process_info(psutil.Process(proc.pid), cache=cache))
			first = cache[proc.pid]
			next(Command.get_process_info(psutil.Process(proc.pid), cache=cache))
			self.assertIs(cache[proc.pid], first, 'cache replaced the Process, losing the baseline')
		finally:
			proc.kill()
			proc.wait()


if __name__ == '__main__':
	unittest.main()


class TestFirstStatsTick(unittest.TestCase):
	"""The t=0 tick is skipped on purpose; the first real sample lands at FIRST_STAT_DELAY."""

	def _first_tick_at(self, frequency):
		"""Replay the monitor's gate and return when the first tick fires, in seconds."""
		now = 0.0
		last = Command._initial_stats_time(now, frequency, Command.FIRST_STAT_DELAY)
		t = 0.0
		while t <= frequency * 2:
			if (t - last) >= frequency:
				return t
			t = round(t + 0.01, 2)
		return None

	def test_no_tick_at_process_start(self):
		"""A tick at t=0 has no interval to measure and always reports cpu 0."""
		last = Command._initial_stats_time(0.0, 20, Command.FIRST_STAT_DELAY)
		self.assertLess(0.0 - last, 20, 'gate opened at t=0 — first tick would report cpu 0')

	def test_first_tick_lands_at_the_delay(self):
		self.assertAlmostEqual(self._first_tick_at(20), Command.FIRST_STAT_DELAY, places=1)

	def test_delay_is_long_enough_to_measure(self):
		"""Below ~10x the 10ms clock granularity the CPU delta is quantisation noise."""
		self.assertGreaterEqual(Command.FIRST_STAT_DELAY, 0.1)

	def test_delay_is_shorter_than_the_cadence(self):
		"""A delay >= frequency would push the first sample out, not pull it in."""
		self.assertGreater(Command.FIRST_STAT_DELAY, 0)
		self.assertLess(Command.FIRST_STAT_DELAY, 20)
