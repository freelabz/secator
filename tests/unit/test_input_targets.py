"""Tests for enable_targets: query-type tasks must not record their inputs as Targets."""
import unittest

from secator.decorators import task
from secator.runners import PythonRunner
from secator.output_types import Info
from secator.tasks.search_vulns import search_vulns
from secator.tasks.searchsploit import searchsploit
from secator.tasks.nmap import nmap


class TestEnableTargets(unittest.TestCase):
	"""A runner records its inputs as Target findings by default (enable_targets=True),
	but a query-type task (enable_targets=False) must not — otherwise the
	search_vulns/searchsploit fan-in query string (`<matched_at>~<product>`) is
	persisted as a phantom Target that pollutes the workspace target list."""

	def test_default_task_emits_input_targets(self):
		@task()
		class TargetEmittingTask(PythonRunner):
			input_types = None
			output_types = [Info]

			def yielder(self):
				yield Info(message="ok")

		results = TargetEmittingTask(inputs=['scanme.example.com']).run()
		targets = [r for r in results if r._type == 'target']
		self.assertTrue(
			any(t.name == 'scanme.example.com' for t in targets),
			"a normal task should record its input as a Target",
		)

	def test_query_task_does_not_emit_input_targets(self):
		@task()
		class QueryTask(PythonRunner):
			input_types = None
			output_types = [Info]
			enable_targets = False

			def yielder(self):
				yield Info(message="ok")

		# The exact shape of a search_vulns fan-in input — must NOT become a Target.
		blob = '1.2.3.4:80,1.2.3.4:443~nginx 1.31.5'
		results = QueryTask(inputs=[blob]).run()
		targets = [r for r in results if r._type == 'target']
		self.assertEqual(targets, [], "a query-type task must not record input Targets")

	def test_query_tasks_have_targets_disabled(self):
		self.assertFalse(search_vulns.enable_targets)
		self.assertFalse(searchsploit.enable_targets)

	def test_target_tasks_keep_targets_enabled(self):
		self.assertTrue(nmap.enable_targets)
		self.assertTrue(PythonRunner.enable_targets)


if __name__ == '__main__':
	unittest.main()
