import glob

import yaml

from secator.runners._helpers import build_extractor_query, substitute_ctx_constants


CTX = {'opts': {'scanners': True, 'probe': False, 'ports': ''}, 'targets': ['1.2.3.4', '5.6.7.8']}


def _ctx(**kw):
	base = {'opts': {}, 'targets': [], 'parent_scope': None, 'ancestor_id': None, 'node_chain_start': False}
	base.update(kw)
	return base


class _AllTruthyOpts:
	"""opts stub whose every key reads truthy, so corpus opt-gates pass and the
	field predicate behind them actually gets exercised by the translator."""
	def get(self, name):
		return True


def _iter_config_extractors():
	"""Yield every extractor dict (has both 'type' and 'condition') in secator/configs/**."""
	for path in glob.glob('secator/configs/**/*.yaml', recursive=True):
		with open(path) as f:
			data = yaml.safe_load(f)
		stack = [data]
		while stack:
			node = stack.pop()
			if isinstance(node, dict):
				if 'type' in node and 'condition' in node:
					yield path, node
				stack.extend(node.values())
			elif isinstance(node, list):
				stack.extend(node)


class TestSubstituteCtxConstants:
	def test_targets_membership_substituted(self):
		out = substitute_ctx_constants('port.host in targets', CTX)
		assert out == "port.host in ['1.2.3.4', '5.6.7.8']"

	def test_truthy_opts_gate_drops_clause(self):
		# opts.scanners True -> gate passes, no residual field predicate.
		assert substitute_ctx_constants('opts.scanners', CTX) == ''

	def test_falsy_opts_gate_returns_none(self):
		assert substitute_ctx_constants('opts.probe', CTX) is None

	def test_missing_opts_gate_is_falsy(self):
		assert substitute_ctx_constants('opts.hunt_secrets', CTX) is None

	def test_len_targets_folded(self):
		assert substitute_ctx_constants('len(targets) == 0', CTX) is None
		assert substitute_ctx_constants('len(targets) == 2', CTX) == ''

	def test_mixed_field_and_gate_and(self):
		out = substitute_ctx_constants('port.host in targets and opts.scanners', CTX)
		assert out == "port.host in ['1.2.3.4', '5.6.7.8']"

	def test_and_gate_false_yields_none(self):
		out = substitute_ctx_constants('port.host in targets and opts.probe', CTX)
		assert out is None

	def test_or_gate_true_matches_all(self):
		ctx = {'opts': {'hunt_secrets': True}, 'targets': []}
		# `not url.verified or opts.hunt_secrets` with the gate truthy -> match everything.
		assert substitute_ctx_constants('not url.verified or opts.hunt_secrets', ctx) == ''

	def test_or_gate_false_leaves_field_predicate(self):
		ctx = {'opts': {'hunt_secrets': False}, 'targets': []}
		out = substitute_ctx_constants('not url.verified or opts.hunt_secrets', ctx)
		assert out == 'not url.verified'

	def test_field_equality_and_len_gate(self):
		# targets empty -> len(targets)==0 True -> residual is the field predicate.
		ctx = {'opts': {}, 'targets': []}
		out = substitute_ctx_constants("item.name == 'net_cidr' and len(targets) == 0", ctx)
		assert out == "item.name == 'net_cidr'"
		# targets present -> gate False -> yield nothing.
		ctx2 = {'opts': {}, 'targets': ['1.2.3.4']}
		assert substitute_ctx_constants("item.name == 'net_cidr' and len(targets) == 0", ctx2) is None

	def test_plain_field_condition_unchanged(self):
		assert substitute_ctx_constants('url.verified', CTX) == 'url.verified'

	def test_empty_condition_returns_empty(self):
		assert substitute_ctx_constants('', CTX) == ''
		assert substitute_ctx_constants(None, CTX) == ''


class TestBuildExtractorQuery:
	def test_type_and_truthy_condition(self):
		q = build_extractor_query({'type': 'url', 'field': 'url', 'condition': 'url.verified'}, _ctx())
		assert q == {'_type': 'url', 'verified': True}

	def test_scope_filter_for_target(self):
		q = build_extractor_query(
			{'type': 'target', 'field': 'name', 'condition': "target.type == 'host'"},
			_ctx(parent_scope='scan-1'))
		assert q['_context.scope'] == 'scan-1'
		assert q['_type'] == 'target' and q['type'] == 'host'

	def test_ancestor_filter(self):
		q = build_extractor_query({'type': 'url', 'condition': 'url.verified'}, _ctx(ancestor_id='anc'))
		assert q['_context.ancestor_id'] == 'anc'

	def test_node_chain_start_skips_ancestor(self):
		q = build_extractor_query(
			{'type': 'url', 'condition': 'url.verified'}, _ctx(ancestor_id='anc', node_chain_start=True))
		assert '_context.ancestor_id' not in q

	def test_scope_only_applies_to_target_type(self):
		# A non-target extractor under a parent_scope still scopes by ancestor, not scope.
		q = build_extractor_query(
			{'type': 'url', 'condition': 'url.verified'}, _ctx(parent_scope='scan-1', ancestor_id='anc'))
		assert '_context.scope' not in q
		assert q['_context.ancestor_id'] == 'anc'

	def test_falsy_gate_returns_none(self):
		assert build_extractor_query(
			{'type': 'url', 'condition': 'opts.probe'}, _ctx(opts={'probe': False})) is None

	def test_item_prefix_rewritten(self):
		q = build_extractor_query({'type': 'url', 'condition': "item.name == 'email_address'"}, _ctx())
		assert q == {'_type': 'url', 'name': 'email_address'}

	def test_not_condition(self):
		q = build_extractor_query({'type': 'subdomain', 'condition': 'not item.verified'}, _ctx())
		assert q == {'_type': 'subdomain', 'verified': False}

	def test_no_condition_matches_type(self):
		q = build_extractor_query({'type': 'target', 'field': 'name'}, _ctx())
		assert q == {'_type': 'target'}

	def test_or_condition(self):
		q = build_extractor_query(
			{'type': 'port', 'field': 'host',
			 'condition': "port.port == 22 or 'ssh' in port.service_name.lower()"}, _ctx())
		assert q['_type'] == 'port'
		assert q['$or'] == [
			{'_type': 'port', 'port': 22},
			{'_type': 'port', 'service_name': {'$regex': '(?i)ssh'}},
		]


def _local_ctx(results, **kw):
	base = {
		'opts': {}, 'targets': [], 'parent_scope': None, 'ancestor_id': None, 'node_chain_start': False,
		'workspace_id': None, 'workspace_name': None, 'drivers': [], 'results': results,
	}
	base.update(kw)
	return base


class TestLocalBackendExtraction:
	def test_filters_verified_urls(self):
		from secator.output_types import Url
		from secator.runners._helpers import run_extractors
		results = [Url(url='http://a', host='a', verified=True), Url(url='http://b', host='b', verified=False)]
		opts = {'targets_': [{'type': 'url', 'field': 'url', 'condition': 'url.verified'}]}
		inputs, _, errors = run_extractors(results, opts, [], ctx=_local_ctx(results))
		assert set(inputs) == {'http://a'}
		assert not errors

	def test_negation_and_case_insensitive_lower(self):
		from secator.output_types import Url, Port
		from secator.runners._helpers import run_extractors
		results = [
			Url(url='http://a', host='a', verified=True),
			Url(url='http://b', host='b', verified=False),
			Port(port=22, ip='1.1.1.1', host='a', service_name='OpenSSH'),
			Port(port=80, ip='1.1.1.2', host='b', service_name='http'),
		]
		# not url.verified -> only the unverified url
		opts = {'targets_': [{'type': 'url', 'field': 'url', 'condition': 'not url.verified'}]}
		inputs, _, errors = run_extractors(results, opts, [], ctx=_local_ctx(results))
		assert set(inputs) == {'http://b'} and not errors
		# 'ssh' in service_name.lower() -> matches OpenSSH case-insensitively
		opts2 = {'targets_': [{'type': 'port', 'field': 'host',
							   'condition': "port.port == 22 or 'ssh' in port.service_name.lower()"}]}
		inputs2, _, errors2 = run_extractors(results, opts2, [], ctx=_local_ctx(results))
		assert set(inputs2) == {'a'} and not errors2


class TestCorpusTranslation:
	def test_every_config_condition_translates_or_raises_explicitly(self):
		ctx = _ctx(opts=_AllTruthyOpts(), targets=['1.2.3.4'], ancestor_id='anc')
		seen = 0
		for path, extractor in _iter_config_extractors():
			seen += 1
			q = build_extractor_query(extractor, dict(ctx))
			assert q is None or isinstance(q, dict), f'{path}: {extractor} -> {q!r}'
		assert seen >= 20, f'expected the full corpus, only walked {seen} extractors'
