from secator.runners._helpers import substitute_ctx_constants


CTX = {'opts': {'scanners': True, 'probe': False, 'ports': ''}, 'targets': ['1.2.3.4', '5.6.7.8']}


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
