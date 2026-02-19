"""Async hook execution with batching support."""
import threading


class BatchQueue:
	"""Thread-safe queue for batching hook calls with deduplication."""

	def __init__(self, hook_fn, batch_size, batch_interval, batch_key='_uuid'):
		"""Initialize batch queue.

		Args:
			hook_fn: The async hook function to call.
			batch_size: Number of items to trigger a flush.
			batch_interval: Seconds before triggering a time-based flush.
			batch_key: Item attribute to use for deduplication.
		"""
		self.hook_fn = hook_fn
		self.batch_size = batch_size
		self.batch_interval = batch_interval
		self.batch_key = batch_key
		self.items = {}  # {key: (runner, item)} - dict for dedup
		self.lock = threading.Lock()

	def add(self, runner, item):
		"""Add item to queue, return True if batch_size reached.

		Args:
			runner: The runner instance.
			item: The item to add.

		Returns:
			bool: True if batch_size reached and flush should be triggered.
		"""
		with self.lock:
			key = getattr(item, self.batch_key, id(item))
			self.items[key] = (runner, item)  # Latest wins
			return len(self.items) >= self.batch_size

	def drain(self):
		"""Remove and return all items.

		Returns:
			list: List of (runner, item) tuples.
		"""
		with self.lock:
			items = list(self.items.values())
			self.items = {}
			return items

	def __len__(self):
		"""Return number of items in queue."""
		with self.lock:
			return len(self.items)
