import unittest

from secator.output_types import Info, Warning
from secator.tasks import httpx


RUN_OPTS = {'sync': True, 'print_item': False, 'print_line': False, 'skip_if_no_inputs': True}


class TestSkippedTaskEmitsInfo(unittest.TestCase):
	"""A task skipped for lack of inputs reports the skip as an Info, never as a Warning.

	The skip is carried by the runner's explicit `skipped` flag (status SKIPPED), so it must
	not inflate the warning count nor be needed to compute the status."""

	def _run_skipped(self):
		runner = httpx(inputs=[], **RUN_OPTS)
		runner.run()
		return runner

	def test_skip_is_an_info_not_a_warning(self):
		runner = self._run_skipped()
		infos = [r for r in runner.results if isinstance(r, Info)]
		self.assertTrue(any(i.message.endswith('skipped (no inputs)') for i in infos), infos)
		self.assertFalse(any(isinstance(r, Warning) for r in runner.results))

	def test_status_is_skipped_and_warning_count_unaffected(self):
		runner = self._run_skipped()
		self.assertTrue(runner.skipped)
		self.assertEqual(runner.status, 'SKIPPED')
		self.assertEqual(len(list(runner.warnings)), 0)
		self.assertEqual(runner.errors_count, 0)
		self.assertEqual(runner.toDict()['status'], 'SKIPPED')

	def test_drivers_receive_the_skip_as_info(self):
		# Every store driver (json/sqlite/mongodb/api) persists through the same on_item hook
		# chain, so asserting what that chain receives covers all backends identically.
		seen = []

		def on_item(runner, item):
			seen.append(item)
			return item

		runner = httpx(inputs=[], hooks={httpx: {'on_item': [on_item]}}, **RUN_OPTS)
		runner.run()
		skips = [i for i in seen if 'skipped (no inputs)' in getattr(i, 'message', '')]
		self.assertEqual(len(skips), 1, seen)
		self.assertEqual(skips[0]._type, 'info')

	def test_skip_info_is_visible_in_output(self):
		runner = self._run_skipped()
		self.assertIn('skipped (no inputs)', runner.output)


if __name__ == '__main__':
	unittest.main()
