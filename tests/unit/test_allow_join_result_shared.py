import threading
import unittest

from celery._state import _set_task_join_will_block, task_join_will_block
from celery.result import allow_join_result, assert_will_not_block

from secator.runners._helpers import allow_join_result_shared


def _overlap(wrapper):
	"""Child A and child B run inside ``wrapper`` in two threads; A exits first, then B
	calls a guarded join. Returns B's exception (None when the join was allowed)."""
	a_in, b_in, a_out = threading.Event(), threading.Event(), threading.Event()
	errors, waits = {}, []

	def child_a():
		with wrapper():
			a_in.set()
			waits.append(b_in.wait(5))
		a_out.set()

	def child_b():
		waits.append(a_in.wait(5))
		with wrapper():
			b_in.set()
			waits.append(a_out.wait(5))
			try:
				assert_will_not_block()
			except RuntimeError as e:
				errors['b'] = e

	threads = [threading.Thread(target=child_a), threading.Thread(target=child_b)]
	for t in threads:
		t.start()
	for t in threads:
		t.join(10)
	# The handshake really happened (A exited while B was still inside).
	assert len(waits) == 3 and all(waits), waits
	assert not any(t.is_alive() for t in threads)
	return errors.get('b')


class TestAllowJoinResultShared(unittest.TestCase):

	def setUp(self):
		self._orig = task_join_will_block()
		_set_task_join_will_block(True)  # inside a worker task: joins are guarded

	def tearDown(self):
		_set_task_join_will_block(self._orig)

	def test_plain_allow_join_result_breaks_on_overlap(self):
		"""The failure being fixed: the first child to exit re-arms the guard under the other."""
		self.assertIsInstance(_overlap(allow_join_result), RuntimeError)

	def test_overlapping_children_keep_joins_allowed(self):
		self.assertIsNone(_overlap(allow_join_result_shared))
		self.assertTrue(task_join_will_block())  # restored once both exited

	def test_nested_in_one_thread(self):
		with allow_join_result_shared():
			with allow_join_result_shared():
				assert_will_not_block()
			assert_will_not_block()  # the inner exit does not re-arm the guard
		self.assertTrue(task_join_will_block())

	def test_exception_still_restores(self):
		with self.assertRaises(ValueError):
			with allow_join_result_shared():
				raise ValueError('boom')
		self.assertTrue(task_join_will_block())
		with allow_join_result_shared():  # the count is back to zero: a new window works
			assert_will_not_block()
		self.assertTrue(task_join_will_block())

	def test_restores_original_false(self):
		_set_task_join_will_block(False)
		with allow_join_result_shared():
			self.assertFalse(task_join_will_block())
		self.assertFalse(task_join_will_block())


if __name__ == '__main__':
	unittest.main()
