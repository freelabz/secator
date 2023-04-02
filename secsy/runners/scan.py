import logging

from secsy.config import ConfigLoader
from secsy.exporters import CsvExporter, JsonExporter, TableExporter
from secsy.output_types import Target
from secsy.runners._base import Runner
from secsy.runners._helpers import run_extractors
from secsy.runners.workflow import Workflow
from secsy.exporters import TableExporter, JsonExporter, CsvExporter

logger = logging.getLogger(__name__)


class Scan(Runner):

	DEFAULT_EXPORTERS = [
		TableExporter,
		JsonExporter,
		CsvExporter
	]
	DEFAULT_FORMAT_OPTIONS = {
		'print_timestamp': True,
		'print_cmd': True,
		'print_line': True,
		'print_item_count': True,
		'raw_yield': False
	}

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
		fmt_opts = self.DEFAULT_FORMAT_OPTIONS.copy()
		fmt_opts['sync'] = sync

		# Log scan start
		self.log_start()

		# Run workflows
		for name, workflow_opts in self.config.workflows.items():

			# Extract opts and and expand target from previous workflows results
			targets, workflow_opts = run_extractors(self.results, workflow_opts or {})
			if not targets:
				targets = self.targets

			# Run workflow
			workflow = Workflow(
				ConfigLoader(name=f'workflows/{name}'),
				targets,
				**self.run_opts
			)
			workflow_results = workflow.run(sync=sync)
			self.results.extend(workflow_results)

		self.done = True
		self.log_results()
		return self.results
