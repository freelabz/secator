from secator.loader import get_configs_by_type
from secator.runners import Workflow


class DynamicWorkflow(Workflow):
	def __init__(self, config):
		self.config = config

	def __call__(self, targets, **kwargs):
		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})
		super().__init__(
			config=self.config,
			inputs=targets,
			results=results,
			hooks=hooks,
			context=context,
			run_opts=kwargs)
		return self

	def delay(self, targets, **kwargs):
		"""Run workflow asynchronously via Celery.

		Args:
			targets: Target(s) for the workflow.
			**kwargs: Run options.

		Returns:
			celery.result.AsyncResult: Celery async result.
		"""
		from secator.celery import run_workflow

		# Extract special kwargs
		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})

		return run_workflow.apply_async(
			kwargs={
				'config': self.config,
				'targets': targets if isinstance(targets, list) else [targets],
				'results': results,
				'run_opts': kwargs,
				'hooks': hooks,
				'context': context
			},
			queue='celery'
		)

	def s(self, targets, **kwargs):
		"""Create a Celery signature for this workflow.

		Args:
			targets: Target(s) for the workflow.
			**kwargs: Run options.

		Returns:
			celery.canvas.Signature: Celery signature.
		"""
		from secator.celery import run_workflow

		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})

		return run_workflow.s(
			config=self.config,
			targets=targets if isinstance(targets, list) else [targets],
			results=results,
			run_opts=kwargs,
			hooks=hooks,
			context=context
		)

	def si(self, targets, **kwargs):
		"""Create an immutable Celery signature for this workflow.

		Args:
			targets: Target(s) for the workflow.
			**kwargs: Run options.

		Returns:
			celery.canvas.Signature: Celery immutable signature.
		"""
		from secator.celery import run_workflow

		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})

		return run_workflow.si(
			config=self.config,
			targets=targets if isinstance(targets, list) else [targets],
			results=results,
			run_opts=kwargs,
			hooks=hooks,
			context=context
		)


DYNAMIC_WORKFLOWS = {}
for workflow in get_configs_by_type('workflow'):
	instance = DynamicWorkflow(workflow)
	DYNAMIC_WORKFLOWS[workflow.name] = instance

globals().update(DYNAMIC_WORKFLOWS)
__all__ = list(DYNAMIC_WORKFLOWS)
