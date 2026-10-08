"""Rich-native AI chat input: the parts testable without a live terminal.

The Live rendering + cbreak reader need a real TTY, so here we drive the input
buffer / queue directly and check the renderable builds.
"""
import unittest

from secator.ai.chat_console import ChatConsole, _ChatRenderable, EXIT
from secator.ai.interactivity import CLIBackend


class TestChatConsole(unittest.TestCase):

	def test_session_name_truncated_to_30(self):
		c = ChatConsole('a-very-long-session-name-that-overflows')
		self.assertEqual(len(c.session_name), 30)
		self.assertEqual(c.session_name, 'a-very-long-session-name-that-')

	def test_type_backspace_submit(self):
		c = ChatConsole('sess')
		for ch in 'hey':
			c._handle_char(ch)
		self.assertEqual(c.buffer, 'hey')
		c._handle_char('\x7f')  # backspace
		self.assertEqual(c.buffer, 'he')
		c._handle_char('\r')    # enter -> submit + clear
		self.assertEqual(c.buffer, '')
		self.assertEqual(c.poll_steers(), ['he'])
		self.assertEqual(c.poll_steers(), [])  # drained

	def test_ctrl_c_and_ctrl_d_submit_exit(self):
		for key in ('\x03', '\x04'):
			c = ChatConsole()
			c._handle_char(key)
			self.assertEqual(c.poll_steers(), [EXIT])

	def test_escape_sequences_ignored(self):
		c = ChatConsole()
		c._handle_char('\x1b')  # start of an arrow-key sequence
		self.assertEqual(c.buffer, '')

	def test_status_set_clear(self):
		c = ChatConsole()
		c.set_status('Detecting intent')
		self.assertEqual(c.status, 'Detecting intent')
		c.clear_status()
		self.assertEqual(c.status, '')

	def test_renderable_builds(self):
		c = ChatConsole('sess')
		c.buffer = 'hello'
		c.set_status('thinking')
		# must build a renderable without raising (idle and busy states)
		self.assertIsNotNone(_ChatRenderable(c).__rich__())
		c.clear_status()
		self.assertIsNotNone(_ChatRenderable(c).__rich__())


class TestCLIBackend(unittest.TestCase):

	def test_non_tty_start_is_noop(self):
		b = CLIBackend()
		b.start_input('s')  # no interactive stdin in the test runner
		self.assertFalse(b.active)
		self.assertEqual(b.poll_steers('s'), [])

	def test_poll_maps_exit_sentinel(self):
		b = CLIBackend()
		b._chat = ChatConsole()
		b._chat._q.put('a message')
		b._chat._q.put(EXIT)
		self.assertEqual(b.poll_steers('s'), ['a message', '/exit'])


if __name__ == '__main__':
	unittest.main()
