from secator.loader import discover_tasks
TASKS = discover_tasks()
__all__ = []
for cls in TASKS:
	name = cls.__name__.split('.')[-1]
	__all__.append(name)
	if getattr(cls, '__external__', False):
		# External tasks: inject directly to avoid exec() SyntaxError when cls.__name__
		# is the fully-qualified module path (e.g. 'secator.tasks.mypilot')
		globals()[name] = cls
	else:
		exec(f'from .{cls.__name__} import {cls.__name__}')
