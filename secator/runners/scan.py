import logging

from secator.config import CONFIG
from secator.runners._base import Runner
from secator.runners.workflow import Workflow
from secator.utils import merge_opts

logger = logging.getLogger(__name__)


class Scan(Runner):

	default_exporters = CONFIG.scans.exporters

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_scan
		return run_scan.delay(args=args, kwargs=kwargs)

	def build_celery_workflow(self):
		"""Build Celery workflow for scan execution.

		Returns:
			celery.Signature: Celery task signature.
		"""
		from celery import chain
		from secator.celery import mark_runner_started, mark_runner_complete
		from secator.template import TemplateLoader

		scan_opts = self.config.options

		# Build chain of workflows
		sigs = []
		for name, workflow_opts in self.config.workflows.items():
			run_opts = self.run_opts.copy()
			run_opts['no_poll'] = True
			opts = merge_opts(scan_opts, workflow_opts, run_opts)
			config = TemplateLoader(name=f'workflows/{name}')
			workflow = Workflow(
				config,
				self.inputs,
				results=self.results,
				run_opts=opts,
				hooks=self._hooks,
				context=self.context.copy()
			)
			celery_workflow = workflow.build_celery_workflow()
			for task_id, task_info in workflow.celery_ids_map.items():
				self.add_subtask(task_id, task_info['name'], task_info['descr'])
			sigs.append(celery_workflow)

		return chain(
			mark_runner_started.si(self).set(queue='results'),
			*sigs,
			mark_runner_complete.s(self).set(queue='results'),
		)
