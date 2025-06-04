import logging
from dotmap import DotMap

from secator.config import CONFIG
from secator.output_types.info import Info
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
		from secator.celery import mark_runner_started, mark_runner_completed
		from secator.template import TemplateLoader

		scan_opts = self.config.options

		# Set hooks and reports
		self.enable_hooks = False   # Celery will handle hooks
		self.enable_reports = True  # Workflow will handle reports
		self.print_item = not self.sync

		# Build chain of workflows
		sigs = []
		sig = None
		for name, workflow_opts in self.config.workflows.items():
			run_opts = self.run_opts.copy()
			run_opts.pop('profiles', None)
			run_opts['no_poll'] = True
			run_opts['caller'] = 'Scan'
			run_opts['has_parent'] = True
			run_opts['enable_reports'] = False
			run_opts['print_profiles'] = False
			opts = merge_opts(scan_opts, workflow_opts, run_opts)
			name = name.split('/')[0]
			config = TemplateLoader(name=f'workflow/{name}')
			if not config:
				raise ValueError(f'Workflow {name} not found')

			# Skip workflow if condition is not met
			condition = workflow_opts.pop('if', None) if workflow_opts else None
			local_ns = {'opts': DotMap(opts)}
			if condition and not eval(condition, {"__builtins__": {}}, local_ns):
				self.add_result(Info(message=f'Skipped workflow {name} because condition is not met: {condition}'))
				continue

			# Build workflow
			workflow = Workflow(
				config,
				self.inputs,
				results=self.results,
				run_opts=opts,
				hooks=self._hooks,
				context=self.context.copy()
			)
			celery_workflow = workflow.build_celery_workflow(chain_previous_results=True)
			for task_id, task_info in workflow.celery_ids_map.items():
				self.add_subtask(task_id, task_info['name'], task_info['descr'])
			sigs.append(celery_workflow)

			for result in workflow.results:
				self.add_result(result, print=False, hooks=False)

		if sigs:
			sig = chain(
				mark_runner_started.si([], self).set(queue='results'),
				*sigs,
				mark_runner_completed.s(self).set(queue='results'),
			)
		return sig
