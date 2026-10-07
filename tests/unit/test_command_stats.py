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

	def test_collect_stats_emits_per_process_with_parent_links(self):
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
			# One Stat PER process (drill-down), not a single aggregate: parent + spawned child.
			self.assertGreaterEqual(len(stats), 2)
			pids = {s.pid for s in stats}
			roots = [s for s in stats if s.parent_pid is None]
			# Exactly one root = the task command itself; its parent is outside the tree.
			self.assertEqual(len(roots), 1)
			self.assertEqual(roots[0].pid, proc.pid)
			# Every non-root points at a parent that is itself in the tree (nestable).
			for s in stats:
				if s.parent_pid is not None:
					self.assertIn(s.parent_pid, pids)
			# Per-process PSS; the subtree sum is the true footprint.
			self.assertTrue(all(s.memory >= 0 for s in stats))
			self.assertGreater(sum(s.memory for s in stats), 0)
		finally:
			proc.kill()
			proc.wait()

	def test_monitor_worker_flag_prepends_worker_root(self):
		import os as _os
		from secator.config import CONFIG
		proc = _spawn_tree()
		inst = Command.__new__(Command)
		inst.process = proc
		inst.cmd_name = 'katana'
		inst.unique_name = 'katana_1'
		inst.memory_limit_mb = -1
		inst.debug = lambda *a, **k: None
		saved = CONFIG.runners.monitor_worker
		CONFIG.set('runners.monitor_worker', True)
		try:
			list(inst._collect_stats({}))  # cpu baseline
			time.sleep(Command.first_stat_delay)
			stats = list(inst._collect_stats({}))
			by_pid = {s.pid: s for s in stats}
			# the worker process (this process) is emitted as the single root, named after the task
			worker = by_pid.get(_os.getpid())
			self.assertIsNotNone(worker, 'worker stat not emitted with monitor_worker on')
			self.assertIsNone(worker.parent_pid)
			self.assertEqual(worker.name, 'katana_1')
			self.assertEqual([s.pid for s in stats if s.parent_pid is None], [_os.getpid()])
			# the task command now nests under the worker (worker -> command -> child)
			self.assertEqual(by_pid[proc.pid].parent_pid, _os.getpid())
		finally:
			CONFIG.set('runners.monitor_worker', saved)
			proc.kill()
			proc.wait()


class TestProcessTreeIsTaskLocal(unittest.TestCase):
	"""#1374: the monitor must walk only the task's own subtree, not every process on the
	host. psutil.children(recursive=True) builds a system-wide ppid map (reads every
	/proc/<pid>/stat) every tick — the fd-churn root cause."""

	def test_tree_is_exactly_the_subtree_and_excludes_host_processes(self):
		parent = _spawn_tree()  # a parent process with a child (see PARENT)
		decoy = None
		try:
			time.sleep(0.3)
			expected = {parent.pid} | {c.pid for c in psutil.Process(parent.pid).children(recursive=True)}
			self.assertGreaterEqual(len(expected), 2, 'expected parent + at least one child')
			self.assertEqual(set(Command._iter_proc_tree(parent.pid)), expected)
			# A process elsewhere on the host (not a descendant of parent) must never appear.
			decoy = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(8)'])
			time.sleep(0.1)
			self.assertNotIn(decoy.pid, set(Command._iter_proc_tree(parent.pid)))
		finally:
			if decoy:
				decoy.kill()
				decoy.wait()
			parent.kill()
			parent.wait()

	def test_monitor_data_is_lean(self):
		proc = _spawn()
		try:
			info = next(Command.get_process_info(psutil.Process(proc.pid), procs={}))
			# fd-heavy fields must not be collected on the hot path (#1374)
			for heavy in ('net_connections', 'connections', 'open_files', 'memory_maps', 'threads'):
				self.assertNotIn(heavy, info, f'{heavy} should not be collected per tick')
			# everything _collect_stats consumes is still present
			for needed in ('pid', 'ppid', 'name', 'cpu_percent', 'pss', 'memory_info'):
				self.assertIn(needed, info)
		finally:
			proc.kill()
			proc.wait()


if __name__ == '__main__':
	unittest.main()
