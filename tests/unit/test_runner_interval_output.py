"""Runner hot-path guarantees: periodic driver updates are throttled for every driver, and
collecting raw output stays linear in the number of lines."""
import unittest
from contextlib import contextmanager
from unittest import mock

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Info, Url
from secator.runners import PythonRunner

N_ITEMS = 300


@task()
class interval_probe(PythonRunner):
	input_types = [HOST]
	output_types = [Url]
	n = N_ITEMS
	raw = False

	def yielder(self):
		for i in range(self.n):
			if self.raw:
				yield f'line {i}'
			else:
				yield Url(url=f'http://h{i}.example.test/', status_code=200)


RUN_OPTS = dict(
	print_item=False, print_line=False, print_start=False, print_end=False,
	quiet=True, sync=True, exporters=[])


@contextmanager
def update_frequency(value):
	"""Temporarily set runners.backend_update_frequency (plain set/restore: the config is a
	pydantic model, so mock.patch.object's delattr-based restore would break it)."""
	previous = CONFIG.runners.backend_update_frequency
	CONFIG.runners.backend_update_frequency = value
	try:
		yield
	finally:
		CONFIG.runners.backend_update_frequency = previous


def _run(**kwargs):
	opts = {**RUN_OPTS, **kwargs}
	runner = interval_probe(['example.test'], **opts)
	items = list(runner)
	return runner, items


class TestIntervalThrottle(unittest.TestCase):

	def test_on_interval_throttled_without_driver_stamp(self):
		"""A hook that never stamps `last_updated_db` itself is still throttled by the runner."""
		calls = []
		with update_frequency(3600):
			_run(hooks={'on_interval': [lambda self: calls.append(1)]}, drivers=[])
		self.assertEqual(len(calls), 1, 'on_interval must fire once per update window, not per item')

	def test_on_interval_every_item_when_frequency_zero(self):
		calls = []
		with update_frequency(0):
			_run(hooks={'on_interval': [lambda self: calls.append(1)]}, drivers=[])
		self.assertEqual(len(calls), N_ITEMS)

	def test_on_interval_disabled_with_minus_one(self):
		calls = []
		with update_frequency(-1):
			_run(hooks={'on_interval': [lambda self: calls.append(1)]}, drivers=[])
		self.assertEqual(calls, [])

	def test_json_driver_does_not_rewrite_runner_info_per_item(self):
		"""The json driver's runner-info rewrite is bounded, and on_end still writes final state."""
		from secator.hooks import json as json_hooks
		writes = []
		real = json_hooks.atomic_json

		def counting(path, *args, **kwargs):
			writes.append(str(path))
			return real(path, *args, **kwargs)

		with update_frequency(3600), mock.patch.object(json_hooks, 'atomic_json', side_effect=counting):
			runner, _ = _run(drivers=['json'])
		info_writes = [p for p in writes if p.endswith('report.json')]
		# on_init + on_start + one interval + on_end (+ run-end), never one per item.
		self.assertLess(len(info_writes), 10, info_writes)
		self.assertEqual(runner.status, 'SUCCESS')


class TestOutputBuffer(unittest.TestCase):

	def test_raw_lines_collected_in_order(self):
		with mock.patch.object(interval_probe, 'raw', True):
			runner, _ = _run(drivers=[])
		self.assertEqual(runner.output, ''.join(f'line {i}\n' for i in range(N_ITEMS)))

	def test_output_str_interface(self):
		runner = interval_probe(['example.test'], **RUN_OPTS, drivers=[])
		self.assertEqual(runner.output, '')
		runner._append_output('a\n')
		runner._append_output('b\n')
		self.assertEqual(runner.output, 'a\nb\n')
		runner.output += 'c'  # += goes through the getter + setter
		self.assertEqual(runner.output, 'a\nb\nc')
		runner.output = runner.output.rstrip('c')
		self.assertEqual(runner.output, 'a\nb\n')
		runner.output = None
		self.assertEqual(runner.output, '')
		runner._append_output('x')
		self.assertEqual(runner.toDict()['output'], 'x')

	def test_info_items_appended_to_output(self):
		runner = interval_probe(['example.test'], **RUN_OPTS, drivers=[])
		info = Info(message='hello')
		runner.add_result(info, print=False)
		self.assertIn('hello', runner.output)

	def test_no_runner_class_shadows_output_property(self):
		"""A class-level `output = ...` on a runner subclass would hide the buffered property."""
		from secator.loader import discover_tasks
		from secator.runners import Command, Runner, Scan, Task, Workflow
		for cls in [Command, Task, Workflow, Scan, PythonRunner, *discover_tasks()]:
			for klass in cls.__mro__:
				if klass is Runner:
					break
				self.assertNotIn('output', vars(klass), f'{klass.__name__} shadows Runner.output')
