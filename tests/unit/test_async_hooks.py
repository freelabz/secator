import unittest
from unittest.mock import MagicMock


class TestBatchQueue(unittest.TestCase):

	def setUp(self):
		self.mock_hook = MagicMock()
		self.mock_hook.__name__ = 'test_hook'

	def test_add_single_item(self):
		"""Item added to queue returns False when under batch_size."""
		from secator.runners._async import BatchQueue
		queue = BatchQueue(self.mock_hook, batch_size=10, batch_interval=5.0)
		item = MagicMock(_uuid='uuid-1')
		result = queue.add(None, item)
		self.assertFalse(result)
		self.assertEqual(len(queue.items), 1)

	def test_deduplication_by_uuid(self):
		"""Later item with same _uuid replaces earlier one."""
		from secator.runners._async import BatchQueue
		queue = BatchQueue(self.mock_hook, batch_size=10, batch_interval=5.0)
		item1 = MagicMock(_uuid='uuid-1', value='first')
		item2 = MagicMock(_uuid='uuid-1', value='second')
		queue.add(None, item1)
		queue.add(None, item2)
		self.assertEqual(len(queue.items), 1)
		_, stored_item = queue.items['uuid-1']
		self.assertEqual(stored_item.value, 'second')

	def test_batch_size_trigger(self):
		"""Returns True when batch_size reached."""
		from secator.runners._async import BatchQueue
		queue = BatchQueue(self.mock_hook, batch_size=2, batch_interval=5.0)
		queue.add(None, MagicMock(_uuid='uuid-1'))
		result = queue.add(None, MagicMock(_uuid='uuid-2'))
		self.assertTrue(result)

	def test_drain_returns_all_and_empties(self):
		"""Drain returns items and clears queue."""
		from secator.runners._async import BatchQueue
		queue = BatchQueue(self.mock_hook, batch_size=10, batch_interval=5.0)
		queue.add(None, MagicMock(_uuid='uuid-1'))
		queue.add(None, MagicMock(_uuid='uuid-2'))
		items = queue.drain()
		self.assertEqual(len(items), 2)
		self.assertEqual(len(queue.items), 0)


class TestAsyncHookManager(unittest.TestCase):

	def setUp(self):
		self.mock_runner = MagicMock()
		self.mock_runner.debug = MagicMock()

	def tearDown(self):
		if hasattr(self, 'manager'):
			self.manager.shutdown()

	def test_submit_creates_queue(self):
		"""First submit creates BatchQueue for hook."""
		from secator.runners._async import AsyncHookManager

		async def mock_async_hook(runner, items):
			pass

		self.manager = AsyncHookManager(self.mock_runner, pool_size=2)
		item = MagicMock(_uuid='uuid-1')
		self.manager.submit(mock_async_hook, 'on_item', item)
		self.assertIn('on_item', self.manager.batch_queues)

	def test_flush_executes_hook_with_items(self):
		"""Flush calls hook with list of items."""
		from secator.runners._async import AsyncHookManager

		received_items = []

		def mock_async_hook(runner, items):
			received_items.extend(items)

		self.manager = AsyncHookManager(self.mock_runner, pool_size=2)
		item1 = MagicMock(_uuid='uuid-1')
		item2 = MagicMock(_uuid='uuid-2')
		self.manager.submit(mock_async_hook, 'on_item', item1)
		self.manager.submit(mock_async_hook, 'on_item', item2)
		errors = self.manager.flush_all()

		self.assertEqual(len(received_items), 2)
		self.assertEqual(len(errors), 0)

	def test_error_collection(self):
		"""Errors collected and returned from flush_all."""
		from secator.runners._async import AsyncHookManager

		def failing_hook(runner, items):
			raise ValueError("Test error")

		self.manager = AsyncHookManager(self.mock_runner, pool_size=2)
		self.manager.submit(failing_hook, 'on_item', MagicMock(_uuid='uuid-1'))
		errors = self.manager.flush_all()

		self.assertEqual(len(errors), 1)
		self.assertIn('Test error', str(errors[0].message))

	def test_flush_on_batch_size(self):
		"""Batch flushed when size limit reached."""
		from secator.runners._async import AsyncHookManager

		call_count = [0]

		def mock_hook(runner, items):
			call_count[0] += 1

		self.manager = AsyncHookManager(
			self.mock_runner,
			pool_size=2,
			default_batch_size=2,
			default_batch_interval=60.0  # Long interval so only size triggers
		)

		# Submit 2 items to trigger batch_size flush
		self.manager.submit(mock_hook, 'on_item', MagicMock(_uuid='uuid-1'))
		self.manager.submit(mock_hook, 'on_item', MagicMock(_uuid='uuid-2'))

		# Wait for thread pool
		self.manager.flush_all()

		self.assertGreaterEqual(call_count[0], 1)


if __name__ == '__main__':
	unittest.main()
