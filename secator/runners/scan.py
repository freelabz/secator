import logging

from secator.config import ConfigLoader
from secator.exporters import CsvExporter, JsonExporter
from secator.runners._base import Runner
from secator.runners._helpers import run_extractors
from secator.runners.workflow import Workflow
from secator.rich import console
from secator.output_types import Target

logger = logging.getLogger(__name__)


class Scan(Runner):

	default_exporters = [
		JsonExporter,
		CsvExporter
	]

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_scan
		return run_scan.delay(args=args, kwargs=kwargs)

	def yielder(self):
		"""Run scan.

		Yields:
			dict: Item yielded from individual workflow tasks.
		"""
		# Yield targets
		for target in self.targets:
			yield Target(name=target, _source=self.config.name, _type='target', _context=self.context)

		# Run workflows
		for name, workflow_opts in self.config.workflows.items():

			# Extract opts and and expand target from previous workflows results
			targets, workflow_opts = run_extractors(self.results, workflow_opts or {}, self.targets)
			if not targets:
				console.log(f'No targets were specified for workflow {name}. Skipping.')
				continue

			# Workflow fmt options
			run_opts = self.run_opts.copy()
			fmt_opts = {
				'json': run_opts.get('json', False),
				'print_item': False,
				'print_start': True,
				'print_run_summary': True,
			}
			run_opts.update(fmt_opts)

			# Run workflow
			workflow = Workflow(
				ConfigLoader(name=f'workflows/{name}'),
				targets,
				results=[],
				run_opts=run_opts,
				hooks=self._hooks,
				context=self.context.copy())

			# Get results
			yield from workflow
