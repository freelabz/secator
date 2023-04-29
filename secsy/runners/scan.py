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

	@classmethod
	def delay(cls, *args, **kwargs):
		from secsy.celery import run_scan
		return run_scan.delay(args=args, kwargs=kwargs)

	def run(self):
		return list(self.__iter__())

	def __iter__(self):
		"""Run scan.

		Yields:
			dict: Item yielded from individual workflow tasks.
		"""
		fmt_opts = self.DEFAULT_FORMAT_OPTIONS.copy()
		fmt_opts['sync'] = self.sync
		self.run_opts.update(fmt_opts)

		# Log scan start
		self.log_start()

		# Add target to results and yield previous results
		_uuid = str(uuid.uuid4())
		self.results = self.results + [
			Target(name=name, _source='scan', _type='target', _uuid=_uuid)
			for name in self.targets
		]
		uuids = [i._uuid for i in self.results]
		yield from self.results
		self.results_count = len(self.results)

		# Init progress
		nworkflows = len(self.config.workflows)
		count = 1

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
			for result in workflow:
				if result._uuid in uuids:
					continue
				uuids.append(result._uuid)
				self.results.append(result)
				self.results_count += 1
				self.run_hooks('on_iter')
				yield result

			# Update scan progress
			self.progress = (count / nworkflows) * 100
			count += 1

		# Filter workflow results
		self.results = self.filter_results()
		self.log_results()
