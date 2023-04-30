import logging
import uuid

from secsy.config import ConfigLoader
from secsy.exporters import CsvExporter, JsonExporter, TableExporter
from secsy.output_types import Target
from secsy.runners._base import Runner
from secsy.runners._helpers import run_extractors
from secsy.runners.workflow import Workflow
from secsy.rich import console

logger = logging.getLogger(__name__)


class Scan(Runner):

	default_exporters = [
		TableExporter,
		JsonExporter,
		CsvExporter
	]

	@classmethod
	def delay(cls, *args, **kwargs):
		from secsy.celery import run_scan
		return run_scan.delay(args=args, kwargs=kwargs)

	def yielder(self):
		"""Run scan.

		Yields:
			dict: Item yielded from individual workflow tasks.
		"""
		# Add target to results and yield previous results
		self.results = self.results + [
			Target(name=name, _source='scan', _type='target', _uuid=str(uuid.uuid4()))
			for name in self.targets
		]
		yield from self.results

		# Run workflows
		for name, workflow_opts in self.config.workflows.items():

			# Extract opts and and expand target from previous workflows results
			targets, workflow_opts = run_extractors(self.results, workflow_opts or {}, self.targets)
			if not targets:
				console.log(f'No targets were specified for workflow {name}. Skipping.')
				continue

			# Run workflow
			workflow = Workflow(
				ConfigLoader(name=f'workflows/{name}'),
				targets,
				workspace_name=self.workspace_name,
				run_opts=self.run_opts,
				hooks=self.hooks,
				context=self.context)

			# Get results
			yield from workflow