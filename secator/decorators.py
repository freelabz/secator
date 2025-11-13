

def task():
	def decorator(cls):
		cls.__task__ = True
		return cls
	return decorator


def util():
	def decorator(cls):
		cls.__util__ = True
		return cls
	return decorator
