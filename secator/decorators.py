import copy
import functools


def cache_copy(func):
	"""Like ``functools.cache``, but return a deep copy of the cached value on every call.

	Use it for lookups whose result callers are free to modify (append tags, extend
	references, ...): a plain ``@cache`` hands every caller the same object, so one caller's
	changes leak into every later result for the same arguments.
	"""
	cached = functools.cache(func)

	@functools.wraps(func)
	def wrapper(*args, **kwargs):
		return copy.deepcopy(cached(*args, **kwargs))

	wrapper.cache_clear = cached.cache_clear
	wrapper.cache_info = cached.cache_info
	return wrapper


def task():
	def decorator(cls):
		cls.__task__ = True
		return cls
	return decorator
