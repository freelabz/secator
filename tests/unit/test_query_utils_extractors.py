import pytest

from secator.query.utils import python_expr_to_mongo


class TestRegexCaseInsensitiveByDefault:
	# startswith/substring/.lower() were all deleted — they are just `~=`, which is
	# case-insensitive by default now (inline (?i), works on json re.search + Mongo $regex).
	def test_regex_gets_inline_ci_flag(self):
		assert python_expr_to_mongo("technology.product ~= 'xrdp'") == {
			'_type': 'technology', 'product': {'$regex': '(?i)xrdp'}
		}

	def test_anchored_regex(self):
		assert python_expr_to_mongo('url._source ~= ^httpx') == {'_type': 'url', '_source': {'$regex': '(?i)^httpx'}}

	def test_negated_regex(self):
		assert python_expr_to_mongo('url.title !~= admin') == {
			'_type': 'url', 'title': {'$not': {'$regex': '(?i)admin'}}
		}


class TestItemPlaceholderNeutral:
	# `item` is a neutral placeholder (the extractor's declared type is authoritative), so it
	# emits a bare field with no _type; a real type prefix still emits _type.
	def test_item_prefix_emits_no_type(self):
		assert python_expr_to_mongo("item.name == 'x'") == {'name': 'x'}
		assert python_expr_to_mongo('item._source ~= ^gf') == {'_source': {'$regex': '(?i)^gf'}}

	def test_real_type_prefix_emits_type(self):
		assert python_expr_to_mongo("target.type == 'host'") == {'_type': 'target', 'type': 'host'}


class TestTruthyAndNot:
	def test_bare_truthy_uses_nin(self):
		assert python_expr_to_mongo('subdomain.verified') == {
			'_type': 'subdomain', 'verified': {'$nin': [None, '', False, 0], '$exists': True}
		}

	def test_not_field_is_ne_true(self):
		# bare `not <field>` (truthy-negation) is DISTINCT from `field not in [...]` ($nin).
		assert python_expr_to_mongo('not subdomain.verified') == {'_type': 'subdomain', 'verified': {'$ne': True}}
		assert python_expr_to_mongo('not item.verified') == {'verified': {'$ne': True}}

	def test_not_in_list_is_nin(self):
		assert python_expr_to_mongo("url.status_code not in [200, 304]") == {
			'_type': 'url', 'status_code': {'$nin': [200, 304]}
		}


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
