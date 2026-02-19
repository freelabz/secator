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


if __name__ == '__main__':
	unittest.main()
