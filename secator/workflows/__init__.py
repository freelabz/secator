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


DYNAMIC_WORKFLOWS = {}
for workflow in get_configs_by_type('workflow'):
	instance = DynamicWorkflow(workflow)
	DYNAMIC_WORKFLOWS[workflow.name] = instance

globals().update(DYNAMIC_WORKFLOWS)
__all__ = list(DYNAMIC_WORKFLOWS)
