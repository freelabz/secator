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

	def test_no_logger_no_error(self):
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		self.assertIsNone(tee._logger)
		# Should not raise even without a logger
		tee.write('line\n')

	def test_logger_receives_clean_line(self):
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		tee._logger = mock_logger
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
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		tee._logger = mock_logger
		tee.write('partial')
		mock_logger.info.assert_not_called()  # no newline yet
		tee.write(' line\n')
		mock_logger.info.assert_called_once_with('partial line')

	def test_flush_drains_partial_buf(self):
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		tee._logger = mock_logger
		tee.write('no newline here')
		mock_logger.info.assert_not_called()
		tee.flush()
		mock_logger.info.assert_called_once_with('no newline here')
		self.assertEqual(tee._buf, '')

	def test_flush_does_not_log_whitespace_only(self):
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		tee._logger = mock_logger
		tee.write('   ')
		tee.flush()
		mock_logger.info.assert_not_called()

	def test_empty_lines_not_logged(self):
		from secator.rich import ConsoleTee
		stream = StringIO()
		with mock.patch('sys.stderr', stream):
			tee = ConsoleTee('stderr')
		mock_logger = mock.MagicMock()
		tee._logger = mock_logger
		tee.write('\n\n\n')
		self.assertEqual(mock_logger.info.call_count, 0)


@mock.patch('sys.stderr', devnull)
class TestSetupFileLogging(unittest.TestCase):

	def test_no_op_when_disabled(self):
		from secator.rich import setup_file_logging, _stderr_tee, _stdout_tee
		original_stderr_logger = _stderr_tee._logger
		cfg = mock.MagicMock()
		cfg.enabled = False
		setup_file_logging(cfg)
		self.assertEqual(_stderr_tee._logger, original_stderr_logger)

	def test_creates_log_file_and_attaches_logger(self):
		from secator.rich import setup_file_logging, _stderr_tee, _stdout_tee
		with tempfile.TemporaryDirectory() as tmpdir:
			log_path = Path(tmpdir) / 'sub' / 'test.log'
			cfg = mock.MagicMock()
			cfg.enabled = True
			cfg.path = log_path
			cfg.max_size_mb = 1
			cfg.backup_count = 2
			setup_file_logging(cfg)
			try:
				self.assertIsNotNone(_stderr_tee._logger)
				self.assertIsNotNone(_stdout_tee._logger)
				self.assertTrue(log_path.parent.exists())
				self.assertTrue(log_path.exists())
			finally:
				_stderr_tee._logger = None
				_stdout_tee._logger = None
				logging.getLogger('secator.console').handlers.clear()

	def test_repeated_calls_do_not_accumulate_handlers(self):
		from secator.rich import setup_file_logging, _stderr_tee, _stdout_tee
		with tempfile.TemporaryDirectory() as tmpdir:
			log_path = Path(tmpdir) / 'test.log'
			cfg = mock.MagicMock()
			cfg.enabled = True
			cfg.path = log_path
			cfg.max_size_mb = 1
			cfg.backup_count = 2
			setup_file_logging(cfg)
			setup_file_logging(cfg)
			logger = logging.getLogger('secator.console')
			try:
				self.assertEqual(len(logger.handlers), 1)
			finally:
				_stderr_tee._logger = None
				_stdout_tee._logger = None
				logger.handlers.clear()
