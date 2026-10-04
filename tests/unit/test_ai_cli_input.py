"""Always-on input bar: the parts testable without a live terminal.

The scroll region + cbreak reader need a real TTY; here we drive the buffer/queue
directly and check the bar draws a sane escape sequence.
"""
import io
import unittest

from secator.ai.chat_bar import ChatBar, EXIT
from secator.ai.interactivity import CLIBackend


class TestChatBar(unittest.TestCase):

	def test_session_name_truncated_to_30(self):
		b = ChatBar('a-very-long-session-name-that-overflows')
		self.assertEqual(len(b.session_name), 30)

	def test_type_backspace_submit(self):
		b = ChatBar('sess')
		for ch in 'hey':
			b._handle_char(ch)
		self.assertEqual(b.buffer, 'hey')
		b._handle_char('\x7f')  # backspace
		self.assertEqual(b.buffer, 'he')
		b._tty = io.StringIO()   # swallow the echo's underlying writes
		b._handle_char('\r')     # enter -> submit + clear
		self.assertEqual(b.buffer, '')
		self.assertEqual(b.poll_steers(), ['he'])
		self.assertEqual(b.poll_steers(), [])

	def test_ctrl_keys_submit_exit(self):
		for key in ('\x03', '\x04'):
			b = ChatBar()
			b._handle_char(key)
			self.assertEqual(b.poll_steers(), [EXIT])

	def test_printable_vs_control(self):
		b = ChatBar()
		b._handle_char('a')
		b._handle_char('\x1b')  # escape seq start -> ignored (no fd to read more)
		self.assertEqual(b.buffer, 'a')

	def test_draw_builds_bar_sequence(self):
		b = ChatBar('recon')
		b.buffer = 'run nmap'
		b._tty = io.StringIO()
		b._draw(cols=40, rows=10)
		out = b._tty.getvalue()
		self.assertIn('recon', out)        # session name in the top rule
		self.assertIn('›', out)            # input prompt
		self.assertIn('run nmap', out)     # the buffer
		self.assertIn('─', out)            # the rules
		self.assertIn('\x1b[1;', out) if False else None  # region set is in _install, not _draw
		self.assertIn('\x1b7', out)        # save cursor (so output above isn't disturbed)
		self.assertIn('\x1b8', out)        # restore cursor


class TestCLIBackend(unittest.TestCase):

	def test_non_tty_start_is_noop(self):
		be = CLIBackend()
		be.start_input('s')  # no interactive stdin in the test runner
		self.assertFalse(be.active)
		self.assertEqual(be.poll_steers('s'), [])

	def test_poll_maps_exit_sentinel(self):
		be = CLIBackend()
		be._bar = ChatBar()
		be._bar._q.put('a message')
		be._bar._q.put(EXIT)
		self.assertEqual(be.poll_steers('s'), ['a message', '/exit'])


if __name__ == '__main__':
	unittest.main()
