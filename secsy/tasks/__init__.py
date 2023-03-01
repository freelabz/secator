from secsy.utils import find_internal_tasks
klasses = find_internal_tasks()
__all__ = [
    cls.__name__
    for cls in klasses
]
for cls in klasses:
    exec(f'from .{cls.__name__} import {cls.__name__}')