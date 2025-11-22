"""Python runner for executing custom Python code."""
import inspect
import logging
from typing import Callable, Any, Iterator

from secator.runners import Runner
from secator.template import TemplateLoader
from secator.output_types import Info, Error


logger = logging.getLogger(__name__)


class PythonRunner(Runner):
	"""Runner class for executing custom Python code.

	This runner allows executing custom Python functions without requiring
	external command-line tools. The function should be a generator that yields
	secator output types.

	Args:
		func (Callable): Python function to execute. Should be a generator that yields OutputType objects.
		inputs (list): List of inputs to pass to the function.
		run_opts (dict): Runner options.
		hooks (dict): User hooks to register.
		validators (dict): User validators to register.
		context (dict): Runner context.

	Example:
		>>> from secator.runners import PythonRunner
		>>> from secator.output_types import Info
		>>>
		>>> def my_function(runner, inputs):
		...     for input_item in inputs:
		...         yield Info(message=f"Processing {input_item}")
		>>>
		>>> runner = PythonRunner(func=my_function, inputs=['target1', 'target2'])
		>>> results = runner.run()
	"""

	# Input field
	input_types = []

	# Output types
	output_types = []

	# Default exporters
	default_exporters = []

	# Profiles
	profiles = []

	def __init__(self, func: Callable = None, inputs=[], **run_opts):
		"""Initialize PythonRunner.

		Args:
			func (Callable): Python function to execute. Should be a generator.
			inputs (list): List of inputs to pass to the function.
			**run_opts: Additional runner options.
		"""
		# Validate function
		if func is None:
			raise ValueError("PythonRunner requires a 'func' parameter")

		if not callable(func):
			raise ValueError("'func' must be a callable")

		# Store the function
		self.func = func

		# Build runner config on-the-fly
		config = TemplateLoader(input={
			'name': run_opts.get('name', func.__name__ if hasattr(func, '__name__') else 'python'),
			'type': 'task',
			'description': run_opts.get('description', func.__doc__ or 'Custom Python runner')
		})

		# Extract run opts
		hooks = run_opts.pop('hooks', {})
		results = run_opts.pop('results', [])
		context = run_opts.pop('context', {})
		node_id = context.get('node_id', None)
		node_name = context.get('node_name', None)
		if node_id:
			config.node_id = node_id
		if node_name:
			config.node_name = context.get('node_name')

		# Call super().__init__
		super().__init__(
			config=config,
			inputs=inputs,
			results=results,
			run_opts=run_opts,
			hooks=hooks,
			validators={},
			context=context)

	def yielder(self) -> Iterator[Any]:
		"""Execute the Python function and yield its results.

		Yields:
			OutputType: Results from the Python function.
		"""
		try:
			# Abort if dry run
			if self.dry_run:
				yield Info(message=f'Would execute: {self.func.__name__}')
				return

			# Check if function is a generator
			if inspect.isgeneratorfunction(self.func):
				# Call as generator
				yield from self.func(self, self.inputs)
			else:
				# Call as regular function and yield result
				result = self.func(self, self.inputs)
				if result is not None:
					yield result

		except Exception as e:
			logger.exception(f"Error executing Python function: {e}")
			yield Error.from_exception(e)

	def build_celery_workflow(self):
		"""Build Celery workflow for Python runner execution.

		Returns:
			celery.Signature: Celery task signature.
		"""
		# For now, PythonRunner doesn't support Celery execution
		# This could be implemented in the future by pickling the function
		raise NotImplementedError("PythonRunner does not support Celery execution yet")
