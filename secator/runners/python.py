"""Python runner for executing custom Python code."""
import logging

from secator.config import CONFIG
from secator.runners import Runner
from secator.template import TemplateLoader


logger = logging.getLogger(__name__)


class PythonRunner(Runner):
	"""Base class for Python-based tasks.

	This runner allows creating tasks that execute custom Python code without
	requiring external command-line tools. Tasks should inherit from this class
	and override the yielder() method.

	Example:
		>>> from secator.decorators import task
		>>> from secator.definitions import HOST
		>>> from secator.output_types import Tag, Url
		>>> from secator.runners import PythonRunner
		>>>
		>>> @task()
		>>> class mytask(PythonRunner):
		...     input_types = [HOST]
		...     output_types = [Tag, Url]
		...     opts = {'option1': {'type': str, 'help': 'An option'}}
		...
		...     def yielder(self):
		...         for target in self.inputs:
		...             yield Url(url=f"http://{target}")
		...             yield Tag(name="scanned", match=target)
	"""
	default_exporters = CONFIG.tasks.exporters
	tags = []
	opts = {}
	default_inputs = None
	profile = 'io'

	def needs_chunking(self, sync):
		return False

	def __init__(self, inputs=[], **run_opts):
		"""Initialize PythonRunner.

		Args:
			inputs (list): List of inputs to pass to the task.
			**run_opts: Additional runner options.
		"""
		# Build runner config on-the-fly
		config = TemplateLoader(input={
			'name': self.__class__.__name__,
			'type': 'task',
			'input_types': self.input_types,
			'description': run_opts.get('description', None)
		})

		# Extract run opts
		hooks = run_opts.pop('hooks', {})
		caller = run_opts.get('caller', None)
		results = run_opts.pop('results', [])
		context = run_opts.pop('context', {})
		node_id = context.get('node_id', None)
		node_name = context.get('node_name', None)
		if node_id:
			config.node_id = node_id
		if node_name:
			config.node_name = node_name
		self.skip_if_no_inputs = run_opts.pop('skip_if_no_inputs', False)
		self.enable_validators = run_opts.pop('enable_validators', True)

		# Prepare validators
		input_validators = []
		if not self.skip_if_no_inputs:
			input_validators.append(self._validate_input_nonempty)
		if not caller:
			input_validators.append(self._validate_chunked_input)
		validators = {'validate_input': input_validators}

		# Call super().__init__
		super().__init__(
			config=config,
			inputs=inputs,
			results=results,
			run_opts=run_opts,
			hooks=hooks,
			validators=validators,
			context=context)

	@staticmethod
	def _validate_input_nonempty(self, inputs):
		"""Input is empty."""
		if self.default_inputs is not None:
			return True
		if not inputs or len(inputs) == 0:
			return False
		return True

	@staticmethod
	def _validate_chunked_input(self, inputs):
		"""Command does not support multiple inputs in non-worker mode. Consider running with a remote worker instead."""
		if len(inputs) > 1:
			return False
		return True

	def yielder(self):
		"""Execute the Python task and yield its results.

		This method should be overridden by subclasses to implement
		the actual task logic.

		Yields:
			OutputType: Results from the Python task.
		"""
		raise NotImplementedError("Subclasses must implement yielder() method")

	@classmethod
	def delay(cls, *args, **kwargs):
		"""Submit task to Celery for async execution."""
		from secator.celery import run_command
		kwargs['sync'] = False
		return run_command.apply_async(
			kwargs={'args': args, 'kwargs': kwargs},
			queue=cls.profile if not callable(cls.profile) else cls.profile(kwargs)
		)

	@classmethod
	def s(cls, *args, **kwargs):
		# TODO: Move this to TaskBase
		from secator.celery import run_command
		profile = cls.profile(kwargs) if callable(cls.profile) else cls.profile
		return run_command.s(cls.__name__, *args, opts=kwargs).set(queue=profile)
