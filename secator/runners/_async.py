"""Async hook execution with batching support."""
import inspect
import threading
from concurrent.futures import ThreadPoolExecutor

from secator.config import CONFIG
from secator.output_types import Error


class AsyncHookManager:
	"""Manages async hook execution with batching and thread pooling."""

	def __init__(self, runner, pool_size=None, default_batch_size=None,
				 default_batch_interval=None):
		"""Initialize async hook manager.

		Args:
			runner: The runner instance.
			pool_size: Thread pool size (default from config).
			default_batch_size: Default batch size (default from config).
			default_batch_interval: Default batch interval in seconds (default from config).
		"""
		self.runner = runner
		self.pool_size = pool_size or CONFIG.runners.async_hook_pool_size
		self.default_batch_size = default_batch_size or CONFIG.runners.async_hook_default_batch_size
		self.default_batch_interval = default_batch_interval or CONFIG.runners.async_hook_default_batch_interval

		self.pool = ThreadPoolExecutor(max_workers=self.pool_size)
		self.batch_queues = {}      # {hook_name: BatchQueue}
		self.errors = []            # Collected errors
		self.flush_timers = {}      # {hook_name: Timer}
		self.lock = threading.Lock()
		self.errors_lock = threading.Lock()
		self.futures = []           # Track submitted futures

	def _get_batch_config(self, hook_fn):
		"""Get batch config for a hook.

		Args:
			hook_fn: The hook function.

		Returns:
			dict: Batch configuration with 'batch_size' and 'batch_interval'.
		"""
		# Check hook module for BATCH_CONFIG
		module = inspect.getmodule(hook_fn)
		if module and hasattr(module, 'BATCH_CONFIG'):
			config = module.BATCH_CONFIG.get(hook_fn.__name__)
			if config:
				return config

		# Fall back to defaults
		return {
			'batch_size': self.default_batch_size,
			'batch_interval': self.default_batch_interval
		}

	def submit(self, hook_fn, hook_name, item):
		"""Submit an item to a hook's batch queue.

		Args:
			hook_fn: The async hook function.
			hook_name: The hook type name (e.g., 'on_item').
			item: The item to batch.
		"""
		with self.lock:
			# Get or create batch queue for this hook
			if hook_name not in self.batch_queues:
				config = self._get_batch_config(hook_fn)
				self.batch_queues[hook_name] = BatchQueue(
					hook_fn,
					batch_size=config['batch_size'],
					batch_interval=config['batch_interval']
				)
				# Start flush timer
				self._start_timer(hook_name)

			queue = self.batch_queues[hook_name]
			should_flush = queue.add(self.runner, item)

			if should_flush:
				self._flush_queue(hook_name)

	def _start_timer(self, hook_name):
		"""Start or reset the flush timer for a hook.

		Args:
			hook_name: The hook type name.
		"""
		# Cancel existing timer if any
		if hook_name in self.flush_timers:
			self.flush_timers[hook_name].cancel()

		queue = self.batch_queues.get(hook_name)
		if not queue:
			return

		timer = threading.Timer(
			queue.batch_interval,
			self._on_timer_flush,
			args=[hook_name]
		)
		timer.daemon = True
		timer.start()
		self.flush_timers[hook_name] = timer

	def _on_timer_flush(self, hook_name):
		"""Timer callback to flush a queue.

		Args:
			hook_name: The hook type name.
		"""
		with self.lock:
			if hook_name in self.batch_queues and len(self.batch_queues[hook_name]) > 0:
				self._flush_queue(hook_name)
				# Restart timer for next batch
				self._start_timer(hook_name)

	def _flush_queue(self, hook_name):
		"""Flush a specific hook's batch queue.

		Args:
			hook_name: The hook type name.
		"""
		queue = self.batch_queues.get(hook_name)
		if not queue:
			return

		items = queue.drain()
		if not items:
			return

		# Submit to thread pool
		future = self.pool.submit(self._execute_batch, queue.hook_fn, hook_name, items)
		self.futures.append(future)

	def _execute_batch(self, hook_fn, hook_name, batch_items):
		"""Execute a batched hook in the thread pool.

		Args:
			hook_fn: The hook function to call.
			hook_name: The hook type name.
			batch_items: List of (runner, item) tuples.
		"""
		try:
			runners = [r for r, _ in batch_items]
			items = [item for _, item in batch_items]
			runner = runners[0] if runners else self.runner

			# Call the hook with list of items
			hook_fn(runner, items)

		except Exception as e:
			error = Error(
				message=f'Async hook "{hook_name}" failed for batch of {len(batch_items)} items: {str(e)}'
			)
			with self.errors_lock:
				self.errors.append(error)

			if self.runner:
				self.runner.debug(
					f'async hook error: {e}',
					obj={'hook': hook_name, 'batch_size': len(batch_items)},
					sub='hooks.async'
				)

	def flush_all(self):
		"""Flush all queues and wait for completion.

		Returns:
			list: List of Error objects from failed hooks.
		"""
		# Cancel all pending timers
		for timer in self.flush_timers.values():
			timer.cancel()
		self.flush_timers.clear()

		# Flush all remaining batches
		with self.lock:
			for hook_name in list(self.batch_queues.keys()):
				self._flush_queue(hook_name)

		# Wait for all futures to complete
		for future in self.futures:
			try:
				future.result()
			except Exception:
				pass  # Errors already collected in _execute_batch

		self.futures.clear()

		return self.errors

	def shutdown(self):
		"""Shutdown the thread pool gracefully."""
		# Cancel all timers
		for timer in self.flush_timers.values():
			timer.cancel()
		self.flush_timers.clear()

		# Shutdown pool
		self.pool.shutdown(wait=True)


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
