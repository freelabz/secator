import pytest

from secator.query.utils import python_expr_to_mongo


class TestStartswith:
	def test_startswith_to_anchored_regex(self):
		assert python_expr_to_mongo("url._source.startswith('httpx')") == {
			'_type': 'url', '_source': {'$regex': '^httpx'}
		}

	def test_startswith_bare_field(self):
		# No type prefix -> just the field key, no _type.
		assert python_expr_to_mongo("_source.startswith('gf')") == {'_source': {'$regex': '^gf'}}

	def test_startswith_escapes_special_chars(self):
		assert python_expr_to_mongo("url.path.startswith('a.b')") == {
			'_type': 'url', 'path': {'$regex': r'^a\.b'}
		}


class TestLowerContains:
	def test_in_lower_to_case_insensitive_regex(self):
		assert python_expr_to_mongo("'ssh' in port.service_name.lower()") == {
			'_type': 'port', 'service_name': {'$regex': '(?i)ssh'}
		}

	def test_in_lower_bare_field(self):
		assert python_expr_to_mongo("'ssh' in service_name.lower()") == {
			'service_name': {'$regex': '(?i)ssh'}
		}

	def test_in_field_case_sensitive_substring(self):
		# `'x' in field` (no .lower()) is case-sensitive substring containment.
		assert python_expr_to_mongo("'445' in target.name") == {
			'_type': 'target', 'name': {'$regex': '445'}
		}


class TestLowerEquality:
	def test_lower_equality_case_insensitive(self):
		assert python_expr_to_mongo("target.name.lower() == 'admin'") == {
			'_type': 'target', 'name': {'$regex': '(?i)^admin$'}
		}


class TestNot:
	def test_bare_truthy_uses_nin(self):
		assert python_expr_to_mongo('subdomain.verified') == {
			'_type': 'subdomain', 'verified': {'$nin': [None, '', False, 0]}
		}

	def test_not_bare_field_is_ne_true(self):
		assert python_expr_to_mongo('not subdomain.verified') == {'_type': 'subdomain', 'verified': {'$ne': True}}

	def test_not_bare_field_no_type(self):
		assert python_expr_to_mongo('not verified') == {'verified': {'$ne': True}}


class TestUntranslatableRaises:
	def test_unknown_function_raises(self):
		with pytest.raises(ValueError):
			python_expr_to_mongo('weird_func(name) == 3')

	def test_bare_garbage_raises(self):
		with pytest.raises(ValueError):
			python_expr_to_mongo("foo(bar)")

	@pytest.mark.parametrize('expr', ['type..field == 1', '.field == 1', 'type. == 1', 'not type..field'])
	def test_malformed_dotted_raises(self, expr):
		with pytest.raises(ValueError):
			python_expr_to_mongo(expr)


class TestLiteralDecode:
	def test_startswith_decodes_escapes(self):
		# The literal is ast.literal_eval'd before re.escape, so `\t` matches a real tab
		# (not a literal backslash-t) — matching the old Python-eval semantics.
		from secator.query.json import match_query
		q = python_expr_to_mongo(r"url._source.startswith('a\tb')")
		assert match_query({'_type': 'url', '_source': 'a\tb-x'}, q)
		assert not match_query({'_type': 'url', '_source': 'atb'}, q)

	def test_mismatched_quote_raises(self):
		with pytest.raises(ValueError):
			python_expr_to_mongo("url._source.startswith('abc)")
