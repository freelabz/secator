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

	def _expand_scan_opts(self):
		"""Expand scan options with 'set' mappings into run_opts.

		Scan options can define a 'set' key that maps option values to workflow-specific
		options. When a scan option is truthy, the 'set' mappings are expanded into
		run_opts so child workflows can resolve them via their opt_aliases.

		Example YAML:
		    options:
		      passive:
		        is_flag: True
		        default: False
		        help: "Passive scan"
		        set:
		          domain_recon_passive: True
		          host_recon_passive: True
		"""
		scan_options = self.config.options.toDict() if self.config.options else {}
		for opt_name, opt_conf in scan_options.items():
			if not isinstance(opt_conf, dict):
				continue
			set_mapping = opt_conf.get('set')
			if not set_mapping:
				continue
			opt_value = self.run_opts.get(opt_name)
			if opt_value is None:
				opt_value = opt_conf.get('default', False)
			if opt_value:
				set_items = set_mapping.toDict() if hasattr(set_mapping, 'toDict') else set_mapping
				for k, v in set_items.items():
					if k not in self.run_opts:
						self.run_opts[k] = v

	def build_celery_workflow(self):
		"""Build Celery workflow for scan execution.

		Returns:
			celery.Signature: Celery task signature.
		"""
		from celery import chain
		from secator.celery import mark_runner_started, mark_runner_completed
		from secator.template import TemplateLoader

		self._expand_scan_opts()

		# Build scan_opts from scan config options. The options key may contain either:
		# - literal values (old format): {threads: 5} → passed through as-is
		# - option definitions (new format): {passive: {is_flag: True, default: False}} →
		#   extract the default value to avoid passing definition dicts to child workflows
		scan_options_raw = self.config.options.toDict() if self.config.options else {}
		scan_opts = {}
		for k, v in scan_options_raw.items():
			if isinstance(v, dict):
				default = v.get('default')
				if default is not None:
					scan_opts[k] = default
			else:
				scan_opts[k] = v

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
			run_opts['reports_folder'] = str(self.reports_folder)
			opts = merge_opts(scan_opts, workflow_opts, run_opts)
			name = name.split('/')[0]
			config = TemplateLoader(name=f'workflow/{name}')
			if not config:
				raise ValueError(f'Workflow {name} not found')

			# Skip workflow if condition is not met
			condition = workflow_opts.pop('if', None) if workflow_opts else None
			local_ns = {'opts': DotMap(opts)}
			safe_globals = {'__builtins__': {'len': len}}
			if condition and not eval(condition, safe_globals, local_ns):
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
