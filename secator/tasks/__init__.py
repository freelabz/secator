from secator.loader import discover_tasks
TASKS = discover_tasks()
__all__ = [
	cls.__name__
	for cls in TASKS
	if not getattr(cls, '__external__', False)
]
for cls in TASKS:
	if getattr(cls, '__external__', False):
		continue
	exec(f'from .{cls.__name__} import {cls.__name__}')
