"""Example Python-based task using PythonRunner.

This is an example of how to create custom tasks that execute Python code
without requiring external command-line tools.
"""
from secator.decorators import task
from secator.output_types import Tag, Url
from secator.runners import PythonRunner


@task()
class example_python(PythonRunner):
	"""Example Python task that analyzes targets."""
	input_types = None  # Accept any input type
	output_types = [Tag, Url]
	tags = ['example', 'python']
	opts = {
		'tag_prefix': {'type': str, 'default': 'analyzed', 'help': 'Prefix for generated tags'}
	}

	def yielder(self):
		"""Execute the custom Python logic."""
		tag_prefix = self.run_opts.get('tag_prefix', 'analyzed')

		for target in self.inputs:
			# Generate a URL for the target
			yield Url(url=f"https://{target}")

			# Generate a tag
			yield Tag(
				name=f"{tag_prefix}_{target}",
				match=target,
				extra_data={'scanned': True}
			)
