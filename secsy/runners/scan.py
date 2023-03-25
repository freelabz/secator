import logging

from secsy.config import ConfigLoader
from secsy.output_types import Target
from secsy.runners._base import Runner
from secsy.runners._helpers import merge_extracted_values
from secsy.runners.workflow import Workflow

logger = logging.getLogger(__name__)


class Scan(Runner):

	def run(self, sync=True, results=[]):
		"""Run scan.

		Yields:
			dict: Item yielded from individual workflow tasks.
		"""
		# Add target to results
		self.sync = sync
		self.results = results + [
			Target(name=name, _source='scan', _type='target')
			for name in self.targets
		]
		self.results = results

		# Log scan start
		self.log_start()

		# Run workflows
		for name, workflow_opts in self.config.workflows.items():

			# Extract opts and and expand target from previous workflows results
			targets, workflow_opts = merge_extracted_values(self.results, workflow_opts or {})
			if not targets:
				targets = self.targets

			# Run workflow
			workflow = Workflow(
				ConfigLoader(name=f'workflows/{name}'),
				targets,
				**self.run_opts
			)
			workflow._print_table = False
			workflow_results = workflow.run(sync=sync)
			self.results.extend(workflow_results)

		self.done = True
		self.log_results()
		return self.results