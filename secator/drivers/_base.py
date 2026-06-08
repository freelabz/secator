class Driver:
	"""Base driver class. Subclass this to create a custom secator driver.

	A driver provides lifecycle hooks that are registered on runners. Drivers can be
	instantiated with custom configuration and passed to runners via the `drivers` parameter.

	Example::

		gcs_driver = GCSDriver(bucket_name='my_bucket')
		runner = Task(config, inputs, drivers=[gcs_driver])

	Serialization note: Driver instances are picklable as long as all __init__ arguments
	are primitive types (str, int, etc.). Module-level connections (DB clients, etc.) should
	be module-level singletons, not stored on the instance.
	"""

	@property
	def name(self):
		return type(self).__name__.lower().replace('driver', '')

	@property
	def hooks(self):
		raise NotImplementedError(f'{type(self).__name__} must implement the hooks property')

	def check(self) -> bool:
		"""Check if the driver is properly configured and can connect to its backend.

		Returns:
			bool: True if the driver is ready, False otherwise.
		"""
		return True
