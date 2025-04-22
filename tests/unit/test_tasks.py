import logging
import unittest
import unittest.mock
import warnings

from secator.definitions import DEBUG
from secator.rich import console
from secator.utils import setup_logging
from secator.utils_test import (FIXTURES_TASKS, INPUTS_TASKS, META_OPTS,
							  CommandOutputTester, mock_command)

level = logging.DEBUG if DEBUG > 0 else logging.ERROR
setup_logging(level)


class TestTasks(unittest.TestCase, CommandOutputTester):

	def setUp(self):
		warnings.simplefilter('ignore', category=ResourceWarning)
		warnings.simplefilter('ignore', category=DeprecationWarning)

	def _valid_fixture(self, cls, fixture):
		if not fixture:
			if len(FIXTURES_TASKS.keys()) == 1: # make test fail.
				raise AssertionError(f'No fixture for {cls.__name__}! Add one to the tests/fixtures directory (must not be an empty file / empty json / empty list).')
			console.print('[dim gold3] skipped (no fixture)[/]')
			return False
		return True

	def test_cmd_converted_schema(self):
		console.print('')

		from secator.config import CONFIG
		if 'debug_command' in CONFIG.debug.component:
			META_OPTS['print_cmd'] = True
			META_OPTS['print_item'] = True

		for cls, fixture in FIXTURES_TASKS.items():
			console.print(f'\t[bold grey35]{cls.__name__} ...[/] ', end='')
			with self.subTest(name=cls.__name__):
				# Validate fixture
				if not self._valid_fixture(cls, fixture):
					continue

				# Run command
				targets = INPUTS_TASKS.get(cls.input_type, 'fake')
				with mock_command(cls, targets, META_OPTS, fixture) as runner:
					self._test_runner_output(
						runner,
						expected_output_types=cls.output_types
					)
