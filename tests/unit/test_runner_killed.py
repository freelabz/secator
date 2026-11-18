"""A runner whose greenlet is killed (GreenletExit) stops its caller instead of ending as an error."""
import unittest
from unittest import mock

from greenlet import GreenletExit

from secator.decorators import task
from secator.output_types import Info
from secator.runners import Command, PythonRunner


@task()
class _Raises(PythonRunner):
	input_types = None
	output_types = [Info]
	exc = None

	def yielder(self):
		yield Info(message='started')
		raise self.exc


@task()
class _Echo(Command):
	cmd = 'echo'
	input_types = None
	output_types = [Info]
	file_flag = None
	input_flag = None
	install_cmd = None


class TestRunnerKilled(unittest.TestCase):

	def test_greenlet_exit_propagates(self):
		_Raises.exc = GreenletExit()
		with self.assertRaises(GreenletExit):
			_Raises(inputs=['t']).run()

	def test_exception_still_ends_as_error(self):
		_Raises.exc = ValueError('boom')
		results = _Raises(inputs=['t']).run()
		self.assertTrue(any(r._type == 'error' and 'boom' in r.message for r in results))

	def test_killed_command_propagates(self):
		with mock.patch.object(_Echo, 'process_line', side_effect=GreenletExit()):
			with self.assertRaises(GreenletExit):
				_Echo(inputs=['hello']).run()

	def test_failing_command_line_still_ends_as_error(self):
		with mock.patch.object(_Echo, 'process_line', side_effect=ValueError('boom')):
			results = _Echo(inputs=['hello']).run()
		self.assertTrue(any(r._type == 'error' and 'boom' in r.message for r in results))
