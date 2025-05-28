

def task():
	def decorator(cls):
		cls.__task__ = True
		return cls
	return decorator
