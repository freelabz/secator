from secator.utils import discover_internal_tasks, discover_external_tasks
INTERNAL_TASKS = discover_internal_tasks()
EXTERNAL_TASKS = discover_external_tasks()
ALL_TASKS = INTERNAL_TASKS + EXTERNAL_TASKS
__all__ = [
    cls.__name__
    for cls in ALL_TASKS
]
for cls in INTERNAL_TASKS:
    exec(f'from .{cls.__name__} import {cls.__name__}')
