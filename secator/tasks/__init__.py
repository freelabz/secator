from secator.utils import discover_tasks
TASKS = discover_tasks()
__all__ = [
    cls.__name__
    for cls in TASKS
]
for cls in TASKS:
    exec(f'from .{cls.__name__} import {cls.__name__}')
