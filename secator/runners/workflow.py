import uuid

from dotmap import DotMap

from secator.config import CONFIG
from secator.output_types import Info
from secator.runners._base import Runner
from secator.runners.task import Task
from secator.tree import build_runner_tree, walk_runner_tree
from secator.utils import merge_opts


class Workflow(Runner):

	default_exporters = CONFIG.workflows.exporters

	@classmethod
	def delay(cls, *args, **kwargs):
		from secator.celery import run_workflow
		return run_workflow.delay(args=args, kwargs=kwargs)

	@classmethod
	def s(cls, *args, **kwargs):
		from secator.celery import run_workflow
		return run_workflow.s(args=args, kwargs=kwargs)

	def build_celery_workflow(self, chain_previous_results=False):
		"""Build Celery workflow for workflow execution.

		Args:
			chain_previous_results (bool): Chain previous results.

		Returns:
			celery.Signature: Celery task signature.
		"""
		from celery import chain
		from secator.celery import mark_runner_started, mark_runner_completed, forward_results

		# Prepare run options
		opts = self.run_opts.copy()
		opts.pop('output', None)
		opts.pop('no_poll', False)
		opts.pop('print_profiles', False)

		# Set hooks and reports
		self.enable_hooks = False   # Celery will handle hooks
		self.enable_reports = True  # Workflow will handle reports

		# Get hooks
		hooks = self._hooks.get(Task, {})
		opts['hooks'] = hooks
		opts['context'] = self.context.copy()
		opts['reports_folder'] = str(self.reports_folder)
		opts['enable_reports'] = False  # Workflow will handle reports
		opts['enable_duplicate_check'] = False  # Workflow will handle duplicate check
		opts['has_parent'] = True
		opts['skip_if_no_inputs'] = True
		opts['caller'] = 'Workflow'

		# Remove workflow config prefix from opts
		for k, v in opts.copy().items():
			if k.startswith(self.config.name + '_'):
				opts[k.replace(self.config.name + '_', '')] = v

		# Forward workflow opts to first task if needed
		forwarded_opts = {}
		if chain_previous_results:
			forwarded_opts = self.dynamic_opts

		# Build workflow tree
		tree = build_runner_tree(self.config)
		ix = 0
		sigs = []

		def process_task(node, force=False):
			from celery import chain, group
			from secator.utils import debug
			nonlocal ix
			sig = None

			if node.id is None:
				return

			if node.type == 'task':
				if node.parent.type == 'group' and not force:
					return

				# Skip task if condition is not met
				condition = node.opts.pop('if', None)
				local_ns = {'opts': DotMap(opts)}
				if condition:
					debug(f'{node.id} evaluating {condition} with opts {opts}', sub=self.config.name)
					result = eval(condition, {"__builtins__": {}}, local_ns)
					if not result:
						debug(f'{node.id} skipped task because condition is not met: {condition}', sub=self.config.name)
						self.add_result(Info(message=f'Skipped task [bold gold3]{node.name}[/] because condition is not met: [bold green]{condition}[/]'))  # noqa: E501
						return

				# Get task class
				task = Task.get_task_class(node.name)

				# Merge task options (order of priority with overrides)
				resolved_opts = merge_opts(self.config.default_options.toDict(), node.opts, opts)
				if ix == 0 and forwarded_opts:
					resolved_opts.update(forwarded_opts)
				resolved_opts['name'] = node.name

				# Create task signature
				task_id = str(uuid.uuid4())
				resolved_opts['context'] = self.context.copy()
				resolved_opts['context']['node_id'] = node.id
				resolved_opts['aliases'] = [node.id, node.name]
				if task.__name__ != node.name:
					resolved_opts['aliases'].append(task.__name__)
				profile = task.profile(resolved_opts) if callable(task.profile) else task.profile
				sig = task.s(self.inputs, **resolved_opts).set(queue=profile, task_id=task_id)
				debug(f'{node.id} sig built', sub=f'workflow.{self.config.name}')
				self.add_subtask(task_id, node.name, resolved_opts.get('description', ''))
				self.output_types.extend(task.output_types)
				ix += 1
			elif node.type == 'group' and node.children:
				tasks = [sig for sig in [process_task(child, force=True) for child in node.children] if sig]
				debug(f'{node.id} group built with {len(tasks)} tasks', sub=self.config.name)
				if len(tasks) == 1:
					debug(f'{node.id} downgraded group to task', sub=self.config.name)
					sig = tasks[0]
				elif len(tasks) > 1:
					sig = group(*tasks)
					last_sig = sigs[-1] if sigs else None
					if sig and isinstance(last_sig, group):  # cannot chain 2 groups without bridge task
						debug(f'{node.id} previous is group, adding bridge task forward_results', sub=self.config.name)
						sigs.append(forward_results.s())
				else:
					debug(f'{node.id} group built with 0 tasks', sub=f'workflow.{self.config.name}')
			elif node.type == 'chain' and node.children:
				tasks = [sig for sig in [process_task(child, force=True) for child in node.children] if sig]
				sig = chain(*tasks) if tasks else None
				debug(f'{node.id} chain built with {len(tasks)} tasks', sub=self.config.name)
			if sig and node.parent.type != 'group':
				debug(f'{node.id} added to workflow', sub=self.config.name)
				sigs.append(sig)
			return sig
		walk_runner_tree(tree, process_task)

		# Build workflow chain with lifecycle management
		start_sig = mark_runner_started.si([], self, enable_hooks=True).set(queue='results')
		if chain_previous_results:
			start_sig = mark_runner_started.s(self, enable_hooks=True).set(queue='results')
		return chain(
			start_sig,
			*sigs,
			mark_runner_completed.s(self, enable_hooks=True).set(queue='results'),
		)

	def get_tasks(self, config, inputs, workflow_opts, run_opts, forwarded_opts={}):
		"""Get tasks recursively as Celery chains / chords.

		Args:
			config (dict): Tasks config dict.
			inputs (list): Inputs.
			workflow_opts (dict): Workflow options.
			run_opts (dict): Run options.
			forwarded_opts (dict): Opts forwarded from parent runner (e.g: scan).
			sync (bool): Synchronous mode (chain of tasks, no chords).

		Returns:
			tuple (List[celery.Signature], List[str]): Celery signatures, Celery task ids.
		"""
		from celery import chain, group
		sigs = []
		sig = None
		ix = 0
		for task_name, task_opts in config.items():
			# Task opts can be None
			task_opts = task_opts or {}

			# If it's a group, process the sublevel tasks as a Celery chord.
			if task_name.startswith('_group'):
				tasks = self.get_tasks(
					task_opts,
					inputs,
					workflow_opts,
					run_opts
				)
				sig = group(*tasks)
			elif task_name == '_chain':
				tasks = self.get_tasks(
					task_opts,
					inputs,
					workflow_opts,
					run_opts
				)
				sig = chain(*tasks)
			else:
				# Skip task if condition is not met
				condition = task_opts.pop('if', None)
				local_ns = {'opts': DotMap(run_opts)}
				if condition and not eval(condition, {"__builtins__": {}}, local_ns):
					self.add_result(Info(message=f'Skipped task [bold gold3]{task_name}[/] because condition is not met: [bold green]{condition}[/]'))  # noqa: E501
					continue

				# Get task class
				task = Task.get_task_class(task_name)

				# Merge task options (order of priority with overrides)
				opts = merge_opts(workflow_opts, task_opts, run_opts)
				if ix == 0 and forwarded_opts:
					opts.update(forwarded_opts)
				opts['name'] = task_name

				# Create task signature
				task_id = str(uuid.uuid4())
				opts['context'] = self.context.copy()
				profile = task.profile(opts) if callable(task.profile) else task.profile
				sig = task.s(inputs, **opts).set(queue=profile, task_id=task_id)
				self.add_subtask(task_id, task_name, task_opts.get('description', ''))
				self.output_types.extend(task.output_types)
				ix += 1
			if sig:
				sigs.append(sig)
		return sigs
