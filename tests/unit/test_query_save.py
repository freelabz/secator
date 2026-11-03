"""`secator q ... --save <name>` stores the raw query expression string.

Bug (#1340): a query containing list/`in` syntax (commas + brackets) was comma-split into a list
by the config value coercion, then rejected because `queries` is ``Dict[str, str]`` -> the save
failed with "Input should be a valid string". The expression must be stored verbatim.
"""
import unittest

from secator.config import Config


class TestQuerySaveRawString(unittest.TestCase):

	def test_query_with_commas_and_brackets_round_trips_as_string(self):
		config = Config.parse()
		expr = "severity in [high, critical] && tags ~= (exploit|kev) && confidence == high"
		config.set('queries.high_priority', expr)
		self.assertIsInstance(config.queries['high_priority'], str)
		self.assertEqual(config.queries['high_priority'], expr)
		self.assertTrue(config.validate(print_errors=False))

	def test_plain_query_still_saved(self):
		config = Config.parse()
		config.set('queries.ports', 'port')
		self.assertEqual(config.queries['ports'], 'port')
		self.assertTrue(config.validate(print_errors=False))


if __name__ == '__main__':
	unittest.main()
