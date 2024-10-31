from secator.cli import ALL_WORKFLOWS


def generate_class(config):
	from secator.runners import Workflow

	class workflow(Workflow):
		def __init__(self, inputs=[], **run_opts):
			hooks = run_opts.pop('hooks', {})
			results = run_opts.pop('results', [])
			context = run_opts.pop('context', {})
			super().__init__(
				config=config,
				inputs=inputs,
				results=results,
				run_opts=run_opts,
				hooks=hooks,
				context=context)
	return workflow, config.name


DYNAMIC_WORKFLOWS = {}
for workflow in ALL_WORKFLOWS:
	cls, name = generate_class(workflow)
	DYNAMIC_WORKFLOWS[name] = cls

globals().update(DYNAMIC_WORKFLOWS)
__all__ = list(DYNAMIC_WORKFLOWS)
