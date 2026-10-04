"""CLIBackend always-on input box: the parts testable without a live terminal.

The box itself (prompt_toolkit in a background thread + patch_stdout) needs a real
TTY, so here we cover the queue plumbing and the end-of-turn line handling by
driving the queue directly.
"""
import unittest

from secator.ai.interactivity import CLIBackend


class TestCLIInputBox(unittest.TestCase):

	def test_non_tty_start_is_noop(self):
		# The test runner has no interactive stdin, so the box must not start.
		b = CLIBackend()
		b.start_input()
		self.assertFalse(b.active)
		self.assertEqual(b.poll_steers('s'), [])

	def test_poll_drains_queue_in_order(self):
		b = CLIBackend()
		b._q.put('hello')
		b._q.put('world')
		self.assertEqual(b.poll_steers('s'), ['hello', 'world'])
		self.assertEqual(b.poll_steers('s'), [])  # drained

	def test_follow_up_returns_typed_message(self):
		b = CLIBackend()
		b._active = True  # simulate an active box
		b._q.put('run a port scan on it')
		self.assertEqual(
			b._handle_follow_up([]),
			{"answer": "run a port scan on it", "extra_iters": 1},
		)

	def test_follow_up_slash_commands(self):
		b = CLIBackend()
		b._active = True
		b._q.put('/exit')
		self.assertIsNone(b._handle_follow_up([]))
		b._q.put('/continue')
		self.assertEqual(b._handle_follow_up([])["answer"], "Continue.")
		b._q.put('/summarize')
		self.assertIn("Summarize", b._handle_follow_up([])["answer"])


if __name__ == '__main__':
	unittest.main()
