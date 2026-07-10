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


import re as _re

from dotmap import DotMap

from secator.output_types import Ip, Port, Subdomain, Tag, Target, Technology, Url, Vulnerability
from secator.query.json import match_query
from secator.runners._helpers import parse_extractor


def _old_eval_pass(item, _type, condition, opts, targets):
	"""Reference: the exact pre-refactor per-item Python eval, kept only to prove the new
	query path selects byte-identical items. Copied from the deleted process_extractor loop."""
	if item._type != _type:
		return False
	if not condition:
		return True
	dm = DotMap(item.toDict())
	local = {'item': dm, _type: dm, 'opts': opts, 'targets': targets}
	safe_globals = {
		'__builtins__': {'len': len},
		're_match': lambda pattern, value: bool(_re.search(pattern, str(value))) if value is not None else False,
	}
	expr = _re.sub(r'([\w.]+)\s*~=\s*(.+?)(?=\s+(?:and|or)\s+|$)', r're_match(\2, \1)', condition)
	return bool(eval(expr, safe_globals, local))


def _golden_findings():
	return [
		Url(url='http://v', host='hv', verified=True, is_root=True, is_directory=False,
			stored_response_path='/r', status_code=200, _source='httpx-1'),
		Url(url='http://u', host='hu', verified=False, is_root=False, is_directory=True,
			stored_response_path='', status_code=0, _source='gf-2'),
		Url(url='http://a', host='ha', verified=True, _source='arjun-3'),
		Subdomain(host='s-verified', domain='example.com', verified=True),
		Subdomain(host='s-unverified', domain='example.com', verified=False),
		Target(name='example.com', type='host'),
		Target(name='a@b.com', type='email'),
		Target(name='example.com:445', type='host'),
		Target(name='http://x', type='url'),
		Port(port=22, ip='1.1.1.1', host='example.com', service_name='OpenSSH'),
		Port(port=80, ip='1.1.1.2', host='other', service_name='http'),
		Ip(ip='1.2.3.4', alive=True),
		Ip(ip='5.6.7.8', alive=False),
		Vulnerability(name='vuln-with-id', id='CVE-1', severity='high'),
		Vulnerability(name='vuln-no-id', id='', severity='low'),
		Technology(match='m1', product='nginx', version='1.0'),
		Technology(match='m2', product='apache', version=None),
		Tag(name='net_cidr', value='v', match='m', category='general'),
		Tag(name='email_address', value='v', match='m', category='general'),
		Tag(name='sqli', value='v', match='m', category='general'),
		Tag(name='url_base', value='v', match='m', category='general'),
	]


# Every distinct condition shape in secator/configs/** (plus the '445' substring form and the
# `name in [...]` form). field is irrelevant to filtering but kept realistic.
GOLDEN_MATRIX = [
	{'type': 'url', 'field': 'url', 'condition': 'url.verified'},                       # truthy bool
	{'type': 'url', 'field': 'url', 'condition': 'url.is_root'},                         # truthy bool
	{'type': 'url', 'field': 'url', 'condition': 'item.is_directory'},                   # truthy bool (item.)
	{'type': 'url', 'field': 'url', 'condition': 'not url.verified'},                    # negated bool
	{'type': 'subdomain', 'field': 'host', 'condition': 'not item.verified'},            # negated bool (item.)
	{'type': 'ip', 'field': 'ip', 'condition': 'ip.alive'},                              # truthy bool
	{'type': 'vulnerability', 'field': 'id', 'condition': 'item.id'},                    # truthy string
	{'type': 'technology', 'field': 'version', 'condition': 'item.version'},             # truthy string (+None)
	{'type': 'target', 'field': 'name', 'condition': "target.type == 'host'"},           # equality
	{'type': 'target', 'field': 'name', 'condition': "item.type == 'url'"},              # equality (item.)
	{'type': 'tag', 'field': 'name', 'condition': "item.name == 'email_address'"},       # equality (item.)
	{'type': 'url', 'field': 'url', 'condition': "item.stored_response_path != ''"},     # inequality str
	{'type': 'url', 'field': 'url', 'condition': 'item.status_code != 0'},               # inequality int
	{'type': 'tag', 'field': 'name', 'condition': "item.name in ['sqli']"},              # in [...]
	{'type': 'url', 'field': 'url', 'condition': "item._source.startswith('httpx')"},    # startswith
	{'type': 'url', 'field': 'url',
	 'condition': "item._source.startswith('urlparser') or item._source.startswith('arjun') "
				  "or item._source.startswith('x8')"},                                    # OR of startswith
	{'type': 'port', 'field': 'host',
	 'condition': "port.port == 22 or 'ssh' in port.service_name.lower()"},              # OR + .lower() in
	{'type': 'target', 'field': 'name', 'condition': "'445' in target.name"},            # substring in field
	{'type': 'target', 'field': 'name', 'condition': 'opts.scanners'},                   # opts gate
	{'type': 'target', 'field': 'name', 'condition': 'not opts.probe'},                  # negated opts gate
	{'type': 'port', 'field': 'port', 'condition': 'port.host in targets and opts.scanners'},   # targets + gate
	{'type': 'tag', 'field': 'name', 'condition': "item.name == 'net_cidr' and len(targets) == 0"},  # len gate
	{'type': 'url', 'field': 'url', 'condition': 'not url.verified or opts.hunt_secrets'},  # OR field + opts gate
]

GOLDEN_CTX_VARIANTS = [
	(DotMap({'probe': True, 'scanners': True, 'hunt_secrets': True, 'ports': '1-100'}), ['example.com']),
	(DotMap({'probe': False, 'scanners': False, 'hunt_secrets': False, 'ports': ''}), []),
	(DotMap({'probe': True, 'scanners': False, 'hunt_secrets': True, 'ports': '80'}), ['example.com', 'other']),
]


class TestDifferentialGolden:
	def test_new_query_path_selects_same_items_as_old_eval(self):
		findings = _golden_findings()
		for extractor in GOLDEN_MATRIX:
			_type, _field, cond, _group_by = parse_extractor(extractor)
			for opts, targets in GOLDEN_CTX_VARIANTS:
				ctx = _ctx(opts=opts, targets=list(targets))
				old = {id(i) for i in findings if _old_eval_pass(i, _type, cond, opts, list(targets))}
				query = build_extractor_query(extractor, ctx)
				new = set()
				if query is not None:
					new = {id(i) for i in findings if match_query(i, query)}
				assert old == new, (
					f'behavior change for {cond!r} (opts={dict(opts)}, targets={targets}): '
					f'query={query!r}; old={old} new={new}'
				)

	def test_full_run_extractors_matches_old_formatted_inputs(self):
		# End-to-end: the new run_extractors output (formatted inputs) equals the old
		# eval's selected items formatted through the same _field logic, incl. group_by.
		from secator.runners._helpers import _format_nested, run_extractors
		findings = _golden_findings()
		opts_dm, targets = GOLDEN_CTX_VARIANTS[0]
		gb_extractor = {'type': 'technology', 'field': '{match}~{product} {version}',
						'condition': 'item.version', 'group_by': '{product} {version}'}
		# Old path: filter by eval, then group_by-format exactly like process_extractor.
		kept = [i for i in findings if _old_eval_pass(i, 'technology', 'item.version', opts_dm, list(targets))]
		groups = {}
		for item in kept:
			d = item.toDict()
			gk = _format_nested('{product} {version}', d)
			val = _format_nested('{match}~{product} {version}', d)
			prefix = val.split('~')[0] if '~' in val else val
			groups.setdefault(gk, [])
			if prefix and prefix not in groups[gk]:
				groups[gk].append(prefix)
		old_out = sorted(','.join(v) + '~' + k for k, v in groups.items())
		inputs, _, errors = run_extractors(
			findings, {'targets_': [gb_extractor]}, [], ctx=_local_ctx(findings, opts=opts_dm, targets=list(targets)))
		assert not errors
		assert sorted(inputs) == old_out


def _dummy_runner():
	from secator.definitions import HOST
	from secator.runners import PythonRunner

	class dummytask(PythonRunner):
		input_types = [HOST]

		def yielder(self):
			return []

	return dummytask(inputs=['x'], skip_if_no_inputs=True)


class TestRunnerErrorStatus:
	def test_status_failure_with_owned_error(self):
		from secator.output_types import Error
		r = _dummy_runner()
		r.started = True
		r.done = True
		assert r.status == 'SUCCESS'
		r.add_result(Error(message='boom'), print=False, hooks=False)
		assert r.status == 'FAILURE'

	def test_hydrate_runner_errors_from_store(self, monkeypatch):
		from secator import celery as celery_mod
		r = _dummy_runner()
		r.started = True
		r.done = True
		assert r.status == 'SUCCESS'
		err_doc = {'_type': 'error', 'message': 'boom', '_source': r.unique_name}
		# Stub the store: only errors come back, never the (huge) findings set.
		monkeypatch.setattr('secator.query.QueryEngine.search', lambda self, *a, **k: [err_doc])
		celery_mod._hydrate_runner_errors(r)
		assert r.status == 'FAILURE'
		assert any(e.message == 'boom' for e in r.self_errors)


class TestCorpusTranslation:
	def test_every_config_condition_translates_or_raises_explicitly(self):
		ctx = _ctx(opts=_AllTruthyOpts(), targets=['1.2.3.4'], ancestor_id='anc')
		seen = 0
		for path, extractor in _iter_config_extractors():
			seen += 1
			q = build_extractor_query(extractor, dict(ctx))
			assert q is None or isinstance(q, dict), f'{path}: {extractor} -> {q!r}'
		assert seen >= 20, f'expected the full corpus, only walked {seen} extractors'
