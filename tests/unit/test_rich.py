import logging
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

devnull = open(os.devnull, 'w')


@mock.patch('sys.stderr', devnull)
class TestConsoleTee(unittest.TestCase):

	def test_write_forwards_to_stream(self):
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
			tee.write('hello\n')
		self.assertEqual(stream.getvalue(), 'hello\n')

	def test_no_handlers_no_error(self):
		"""When _console_logger has no handlers, ConsoleTee should not raise."""
		import secator.rich as rich_module
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		mock_logger.handlers = []
		with mock.patch.object(rich_module, '_console_logger', mock_logger):
			tee.write('line\n')
		mock_logger.info.assert_not_called()

	def test_logger_receives_clean_line(self):
		import secator.rich as rich_module
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		mock_logger.handlers = [mock.MagicMock()]
		with mock.patch.object(rich_module, '_console_logger', mock_logger):
			tee.write('\x1b[32mhello\x1b[0m\n')
		mock_logger.info.assert_called_once_with('hello')

	def test_ansi_codes_stripped(self):
		from secator.rich import _ANSI_ESCAPE
		dirty = '\x1b[1m\x1b[32mINF\x1b[0m some message'
		clean = _ANSI_ESCAPE.sub('', dirty)
		self.assertEqual(clean, 'INF some message')

	def test_ansi_regex_strips_cursor_hide(self):
		from secator.rich import _ANSI_ESCAPE
		# ?-prefixed CSI sequence (e.g. cursor hide used by Rich Live)
		dirty = '\x1b[?25lsome text\x1b[?25h'
		clean = _ANSI_ESCAPE.sub('', dirty)
		self.assertEqual(clean, 'some text')

	def test_partial_line_buffered(self):
		import secator.rich as rich_module
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		mock_logger.handlers = [mock.MagicMock()]
		with mock.patch.object(rich_module, '_console_logger', mock_logger):
			tee.write('partial')
			mock_logger.info.assert_not_called()  # no newline yet
			tee.write(' line\n')
			mock_logger.info.assert_called_once_with('partial line')

	def test_flush_drains_partial_buf(self):
		import secator.rich as rich_module
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		mock_logger.handlers = [mock.MagicMock()]
		with mock.patch.object(rich_module, '_console_logger', mock_logger):
			tee.write('no newline here')
			mock_logger.info.assert_not_called()
			tee.flush()
			mock_logger.info.assert_called_once_with('no newline here')
		self.assertEqual(tee._buf, '')

	def test_flush_does_not_log_whitespace_only(self):
		import secator.rich as rich_module
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		mock_logger.handlers = [mock.MagicMock()]
		with mock.patch.object(rich_module, '_console_logger', mock_logger):
			tee.write('   ')
			tee.flush()
		mock_logger.info.assert_not_called()

	def test_empty_lines_not_logged(self):
		import secator.rich as rich_module
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		mock_logger.handlers = [mock.MagicMock()]
		with mock.patch.object(rich_module, '_console_logger', mock_logger):
			tee.write('\n\n\n')
		self.assertEqual(mock_logger.info.call_count, 0)


@mock.patch('sys.stderr', devnull)
class TestLogHandlers(unittest.TestCase):

	def test_add_log_handler_creates_file(self):
		from secator.rich import add_log_handler, remove_log_handler
		with tempfile.TemporaryDirectory() as tmpdir:
			log_path = Path(tmpdir) / 'sub' / 'test.log'
			handler = add_log_handler(log_path)
			try:
				self.assertTrue(log_path.parent.exists())
				logger = logging.getLogger('secator.console')
				self.assertIn(handler, logger.handlers)
			finally:
				remove_log_handler(handler)

	def test_remove_log_handler_detaches(self):
		from secator.rich import add_log_handler, remove_log_handler
		with tempfile.TemporaryDirectory() as tmpdir:
			log_path = Path(tmpdir) / 'test.log'
			handler = add_log_handler(log_path)
			remove_log_handler(handler)
			logger = logging.getLogger('secator.console')
			self.assertNotIn(handler, logger.handlers)

	def test_remove_none_is_noop(self):
		from secator.rich import remove_log_handler
		# Should not raise
		remove_log_handler(None)
