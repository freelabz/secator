"""Tests for PythonRunner."""
import unittest
from secator.runners import PythonRunner
from secator.output_types import Info, Url, Vulnerability


class TestPythonRunner(unittest.TestCase):
	"""Test suite for PythonRunner."""

	def test_init_without_func(self):
		"""Test that PythonRunner raises ValueError when initialized without a function."""
		with self.assertRaises(ValueError) as context:
			PythonRunner(inputs=['test'])
		self.assertIn("requires a 'func' parameter", str(context.exception))

	def test_init_with_non_callable(self):
		"""Test that PythonRunner raises ValueError when func is not callable."""
		with self.assertRaises(ValueError) as context:
			PythonRunner(func="not a function", inputs=['test'])
		self.assertIn("must be a callable", str(context.exception))

	def test_simple_generator_function(self):
		"""Test PythonRunner with a simple generator function."""
		def simple_func(runner, inputs):
			for inp in inputs:
				yield Info(message=f"Processing {inp}")

		runner = PythonRunner(func=simple_func, inputs=['target1', 'target2'])
		results = runner.run()

		# Filter Info results (excluding Target results)
		info_results = [r for r in results if r._type == 'info' and 'Processing' in r.message]
		self.assertEqual(len(info_results), 2)
		self.assertEqual(info_results[0].message, "Processing target1")
		self.assertEqual(info_results[1].message, "Processing target2")

	def test_regular_function(self):
		"""Test PythonRunner with a regular (non-generator) function."""
		def simple_func(runner, inputs):
			return Info(message=f"Processed {len(inputs)} inputs")

		runner = PythonRunner(func=simple_func, inputs=['target1', 'target2'])
		results = runner.run()

		# Filter Info results (excluding Target results)
		info_results = [r for r in results if r._type == 'info']
		self.assertEqual(len(info_results), 1)
		self.assertEqual(info_results[0].message, "Processed 2 inputs")

	def test_function_with_complex_output(self):
		"""Test PythonRunner with a function that yields different output types."""
		def complex_func(runner, inputs):
			yield Info(message="Starting scan")
			for inp in inputs:
				if "vuln" in inp:
					yield Vulnerability(
						name="Test Vulnerability",
						severity="high",
						confidence="high",
						matched_at=inp
					)
				else:
					yield Url(url=f"http://{inp}")
			yield Info(message="Scan complete")

		runner = PythonRunner(
			func=complex_func,
			inputs=['example.com', 'vuln.example.org']
		)
		results = runner.run()

		# Count different result types
		info_results = [r for r in results if r._type == 'info']
		url_results = [r for r in results if r._type == 'url']
		vuln_results = [r for r in results if r._type == 'vulnerability']

		self.assertEqual(len(info_results), 2)
		self.assertEqual(len(url_results), 1)
		self.assertEqual(len(vuln_results), 1)
		self.assertEqual(vuln_results[0].name, "Test Vulnerability")

	def test_function_with_error(self):
		"""Test PythonRunner with a function that raises an exception."""
		def error_func(runner, inputs):
			yield Info(message="Before error")
			raise ValueError("Test error")

		runner = PythonRunner(func=error_func, inputs=['target1'])
		results = runner.run()

		# Check that we got results including the error
		error_results = [r for r in results if r._type == 'error']
		self.assertEqual(len(error_results), 1)
		self.assertIn("Test error", error_results[0].message)

	def test_dry_run(self):
		"""Test PythonRunner in dry run mode."""
		def simple_func(runner, inputs):
			yield Info(message="This should not execute")

		runner = PythonRunner(func=simple_func, inputs=['target1'], dry_run=True)
		results = runner.run()

		# In dry run, should get an info message about what would execute
		info_results = [r for r in results if r._type == 'info']
		self.assertTrue(any('Would execute' in r.message for r in info_results))

	def test_runner_name_from_function(self):
		"""Test that runner name is derived from function name."""
		def my_custom_function(runner, inputs):
			yield Info(message="test")

		runner = PythonRunner(func=my_custom_function, inputs=['target1'])
		self.assertEqual(runner.name, 'my_custom_function')

	def test_runner_with_custom_name(self):
		"""Test that custom name can be provided."""
		def some_func(runner, inputs):
			yield Info(message="test")

		runner = PythonRunner(func=some_func, inputs=['target1'], name='CustomName')
		self.assertEqual(runner.name, 'CustomName')

	def test_access_to_runner_context(self):
		"""Test that the function has access to the runner instance."""
		def context_func(runner, inputs):
			# Access runner properties
			yield Info(message=f"Runner name: {runner.name}")
			yield Info(message=f"Input count: {len(runner.inputs)}")

		runner = PythonRunner(func=context_func, inputs=['a', 'b', 'c'])
		results = runner.run()

		info_results = [r for r in results if r._type == 'info']
		messages = [r.message for r in info_results]

		self.assertTrue(any('Runner name' in m for m in messages))
		self.assertTrue(any('Input count: 3' in m for m in messages))

	def test_empty_inputs(self):
		"""Test PythonRunner with empty inputs list."""
		def simple_func(runner, inputs):
			if not inputs:
				yield Info(message="No inputs provided")
			for inp in inputs:
				yield Info(message=f"Processing {inp}")

		runner = PythonRunner(func=simple_func, inputs=[])
		results = runner.run()

		info_results = [r for r in results if r._type == 'info' and 'No inputs' in r.message]
		self.assertEqual(len(info_results), 1)

	def test_function_returning_none(self):
		"""Test PythonRunner with a function that returns None."""
		def none_func(runner, inputs):
			# Do some processing but return nothing
			pass

		runner = PythonRunner(func=none_func, inputs=['target1'])
		results = runner.run()

		# Should not crash, may have Target results but no other results
		self.assertIsInstance(results, list)


if __name__ == '__main__':
	unittest.main()
