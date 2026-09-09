"""`secator q -f <field>` formatting.

Bug: a bare `-f port` was treated as the *type* `port` (which is in the results), so it fell to
the OutputType's ``__str__`` (the ``host:port`` couple) instead of the ``port`` field. It must
behave like ``-f port.port`` when a single type is present.
"""
import unittest

from secator.cli import _apply_format


class TestApplyFormatBareField(unittest.TestCase):

	def test_bare_token_that_is_a_field_emits_the_field(self):
		results = {'port': [{'host': '10.0.0.1', 'port': 443}, {'host': 'h2', 'port': 80}]}
		out = _apply_format(dict(results), 'port')
		self.assertEqual(out['port'], ['443', '80'])  # the port field, NOT '10.0.0.1:443'

	def test_bare_token_matches_dotted_form(self):
		results = {'port': [{'host': 'h', 'port': 443}, {'host': 'h', 'port': 8080}]}
		self.assertEqual(
			_apply_format(dict(results), 'port'),
			_apply_format(dict(results), 'port.port'),
		)

	def test_bare_field_not_matching_type_name_still_works(self):
		# Unchanged path: a bare field that isn't the type name resolves on the single type.
		results = {'port': [{'host': 'h1', 'port': 443}, {'host': 'h2', 'port': 80}]}
		out = _apply_format(dict(results), 'host')
		self.assertEqual(out['port'], ['h1', 'h2'])


if __name__ == '__main__':
	unittest.main()
