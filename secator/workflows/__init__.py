from secator.cli import ALL_WORKFLOWS
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
for workflow in ALL_WORKFLOWS:
	instance = DynamicWorkflow(workflow)
	DYNAMIC_WORKFLOWS[workflow.name] = instance

globals().update(DYNAMIC_WORKFLOWS)
__all__ = list(DYNAMIC_WORKFLOWS)
