import importlib
import re
from secator.loader import discover_tasks

TASKS = discover_tasks()
__all__ = [
	cls.__name__
	for cls in TASKS
]
for cls in TASKS:
	name = cls.__name__
	if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
		raise ValueError(f'Invalid task class name: {name}')
	importlib.import_module(f'.{name}', __package__)
