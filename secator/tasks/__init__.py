from secator.loader import discover_tasks, discover_utils

TASKS = discover_tasks()
UTILS = discover_utils()
ALL = TASKS + UTILS
__all__ = [
    cls.__name__
    for cls in ALL
]
for cls in ALL:
    exec(f'from .{cls.__name__} import {cls.__name__}')
