"""Tests for PythonRunner."""
import unittest
from secator.decorators import task
from secator.runners import PythonRunner
from secator.output_types import Info, Url, Vulnerability, Tag


class TestPythonRunner(unittest.TestCase):
	"""Test suite for PythonRunner."""

	def test_simple_task(self):
		"""Test PythonRunner with a simple task that yields Info messages."""
		@task()
		class SimpleTask(PythonRunner):
			input_types = None  # Accept any input type
			output_types = [Info]

			def yielder(self):
				for inp in self.inputs:
					yield Info(message=f"Processing {inp}")

		runner = SimpleTask(inputs=['target1'])
		results = runner.run()

		# Filter Info results (excluding Target results)
		info_results = [r for r in results if r._type == 'info' and 'Processing' in r.message]
		self.assertEqual(len(info_results), 1)
		self.assertEqual(info_results[0].message, "Processing target1")

	def test_task_with_multiple_output_types(self):
		"""Test PythonRunner task that yields different output types."""
		@task()
		class ComplexTask(PythonRunner):
			input_types = None
			output_types = [Info, Url, Vulnerability]

			def yielder(self):
				yield Info(message="Starting scan")
				for inp in self.inputs:
					if "vuln" in inp:
						yield Vulnerability(
							name="Test Vulnerability",
							severity="high",
							confidence="high",
							matched_at=inp
						)
					yield Url(url=f"http://{inp}")
				yield Info(message="Scan complete")

		runner = ComplexTask(inputs=['example.com'])
		results = runner.run()

		# Count different result types
		info_results = [r for r in results if r._type == 'info']
		url_results = [r for r in results if r._type == 'url']

		self.assertEqual(len(info_results), 2)
		self.assertEqual(len(url_results), 1)

	def test_task_with_options(self):
		"""Test PythonRunner task with custom options."""
		@task()
		class TaskWithOpts(PythonRunner):
			input_types = None
			output_types = [Tag]
			opts = {
				'tag_name': {'type': str, 'default': 'default', 'help': 'Tag name to use'}
			}

			def yielder(self):
				tag_name = self.run_opts.get('tag_name', 'default')
				for inp in self.inputs:
					yield Tag(name=tag_name, value=inp, match=inp)

		runner = TaskWithOpts(inputs=['target1'], tag_name='custom')
		results = runner.run()
		tag_results = [r for r in results if r._type == 'tag']

		self.assertEqual(len(tag_results), 1)
		self.assertEqual(tag_results[0].name, 'custom')
		self.assertEqual(tag_results[0].value, 'target1')
		self.assertEqual(tag_results[0].match, 'target1')

	def test_task_name(self):
		"""Test that task name is derived from class name."""
		@task()
		class MyCustomTask(PythonRunner):
			input_types = None
			output_types = [Info]

			def yielder(self):
				yield Info(message="test")

		runner = MyCustomTask(inputs=['target1'])
		self.assertEqual(runner.name, 'MyCustomTask')

	def test_access_to_runner_context(self):
		"""Test that the task has access to the runner context."""
		@task()
		class ContextTask(PythonRunner):
			input_types = None
			output_types = [Info]

			def yielder(self):
				yield Info(message=f"Runner name: {self.name}")
				yield Info(message=f"Input count: {len(self.inputs)}")

		runner = ContextTask(inputs=['example.com'])
		results = runner.run()

		info_results = [r for r in results if r._type == 'info']
		messages = [r.message for r in info_results]

		self.assertTrue(any('Runner name' in m for m in messages))
		self.assertTrue(any('Input count: 1' in m for m in messages))

	def test_inputs_validator_failed_no_targets(self):
		"""Test that validation fails when no inputs are provided."""
		@task()
		class TaskNeedsInput(PythonRunner):
			input_types = None
			output_types = [Info]

			def yielder(self):
				yield Info(message="test")

		runner = TaskNeedsInput(inputs=[])
		results = runner.run()
		errors = [r for r in results if r._type == 'error']
		messages = [e.message for e in errors]
		self.assertIn("Validator failed: Input is empty.", messages)
		self.assertFalse(runner.inputs_valid)

	def test_inputs_validator_failed_multiple_targets(self):
		"""Test that validation fails with multiple inputs in non-worker mode."""
		@task()
		class SingleInputTask(PythonRunner):
			input_types = None
			output_types = [Info]

			def yielder(self):
				yield Info(message="test")

		runner = SingleInputTask(inputs=['target1', 'target2'])
		results = runner.run()
		errors = [r for r in results if r._type == 'error']
		messages = [e.message for e in errors]
		expected_msg = "Validator failed: Command does not support multiple inputs in non-worker mode. " \
			"Consider running with a remote worker instead."
		self.assertIn(expected_msg, messages)
		self.assertFalse(runner.inputs_valid)

	def test_not_implemented_error(self):
		"""Test that base PythonRunner raises NotImplementedError if yielder not overridden."""
		# This would only happen if someone instantiates PythonRunner directly
		# without subclassing, which shouldn't happen in practice
		with self.assertRaises(NotImplementedError):
			# Manually call yielder to trigger NotImplementedError
			runner = PythonRunner(inputs=['test'])
			list(runner.yielder())


if __name__ == '__main__':
	unittest.main()
