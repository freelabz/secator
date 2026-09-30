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


# A parent that spawns one child, so the tree has >1 process (like a task that spawns a browser).
PARENT = (
	'import subprocess, sys, time\n'
	'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"])\n'
	'sys.stdout.write("READY\\n")\n'
	'sys.stdout.flush()\n'
	't = time.time()\n'
	'while time.time() - t < 6:\n'
	'\tpass\n'
)


def _spawn_tree():
	proc = subprocess.Popen([sys.executable, '-c', PARENT], stdout=subprocess.PIPE, text=True)
	assert proc.stdout.readline().strip() == 'READY', 'parent never signalled readiness'
	return proc


class TestProcessTreeMemory(unittest.TestCase):
	"""Memory is reported for the whole process tree, once, using PSS (no shared-page double-count)."""

	def test_get_process_info_includes_pss(self):
		proc = _spawn()
		procs = {}
		try:
			info = next(Command.get_process_info(psutil.Process(proc.pid), procs=procs))
			self.assertIn('pss', info)
			self.assertGreater(info['pss'], 0)
		finally:
			proc.kill()
			proc.wait()

	def test_collect_stats_emits_one_aggregate_for_the_tree(self):
		proc = _spawn_tree()
		inst = Command.__new__(Command)
		inst.process = proc
		inst.cmd_name = 'python-tree'
		inst.memory_limit_mb = -1
		inst.debug = lambda *a, **k: None
		try:
			list(inst._collect_stats({}))  # cpu baseline
			time.sleep(Command.first_stat_delay)
			stats = list(inst._collect_stats({}))
			# ONE Stat for the whole tree, not one per process
			self.assertEqual(len(stats), 1)
			stat = stats[0]
			self.assertEqual(stat.name, 'python-tree')   # the command (parent), not a child pid
			self.assertEqual(stat.pid, proc.pid)
			self.assertGreater(stat.memory, 0)
			# the tree total covers parent + spawned child, with a per-process breakdown kept aside
			self.assertGreaterEqual(len(stat.extra_data.get('processes', [])), 2)
		finally:
			proc.kill()
			proc.wait()


if __name__ == '__main__':
	unittest.main()
