import logging

from secator.template import TemplateLoader
from secator.config import CONFIG
from secator.runners._base import Runner
from secator.runners._helpers import run_extractors
from secator.runners.workflow import Workflow

logger = logging.getLogger(__name__)


class Scan(Runner):

	default_exporters = CONFIG.scans.exporters

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_scan
		return run_scan.delay(args=args, kwargs=kwargs)

	def yielder(self):
		"""Run scan.

		Yields:
			dict: Item yielded from individual workflow tasks.
		"""
		for name, workflow_opts in self.config.workflows.items():

			# Extract opts and and expand target from previous workflows results
			targets, workflow_opts = run_extractors(self.results, workflow_opts or {}, self.targets)

			# Run workflow
			run_opts = self.run_opts.copy()
			run_opts['print_item'] = False
			workflow = Workflow(
				TemplateLoader(name=f'workflows/{name}'),
				targets,
				results=[],
				run_opts=run_opts,
				hooks=self._hooks,
				context=self.context.copy())

			# Get results
			yield from workflow
