"""Fold extractor-specific runtime constants (opts.*/targets/len(targets)) out of a condition
before it is translated to a query.

This is the one piece that ``python_expr_to_mongo`` (a pure string->query translator) cannot do:
it needs the run's *runtime* opts/targets values, and it must boolean-simplify the residual so
an OR-mixed gate like ``not url.verified or opts.hunt_secrets`` collapses correctly (a truthy
gate => match everything; a falsy gate => the remaining field predicate). Everything else — the
field predicates themselves — is left as a string for ``python_expr_to_mongo``.
"""

import ast
import operator
import re

# Conditions that reference runtime constants (opts.*/targets/len(targets)) need folding.
# Others pass straight through — notably `~=` regex conditions, which are not valid Python
# and would break ast.parse. ponytail: a condition mixing `~=` with opts/targets in one
# expression would fail to parse; none ship, revisit if one is added.
_CTX_TOKEN_RE = re.compile(r'\b(?:opts|targets)\b')


_COMPARE_OPS = {
	ast.Eq: operator.eq,
	ast.NotEq: operator.ne,
	ast.Lt: operator.lt,
	ast.LtE: operator.le,
	ast.Gt: operator.gt,
	ast.GtE: operator.ge,
	ast.In: lambda a, b: a in b,
	ast.NotIn: lambda a, b: a not in b,
}


def _opts_get(opts, name):
	"""Read an opt value from a dict or DotMap, returning None when absent."""
	if hasattr(opts, 'get'):
		return opts.get(name)
	return getattr(opts, name, None)


def _fold(node, opts, targets):
	"""Fold ctx-constants (opts.*/targets/len(targets)) in an AST node.

	Returns (is_const, value_or_node): if is_const, value is a concrete Python value;
	otherwise value is an AST node with any constant children substituted in place.
	"""
	# Substitute `targets` -> list literal.
	if isinstance(node, ast.Name):
		if node.id == 'targets':
			return True, list(targets)
		return False, node

	# Substitute `opts.<name>` -> its runtime value; leave finding-field access as an AST node.
	if isinstance(node, ast.Attribute):
		if isinstance(node.value, ast.Name) and node.value.id == 'opts':
			return True, _opts_get(opts, node.attr)
		return False, node

	if isinstance(node, ast.Constant):
		return True, node.value

	# Fold constant container literals (opts.mode in ('attack', 'chat')) so a runtime-only `in`
	# gate collapses instead of leaking a fieldless expr to python_expr_to_mongo.
	# ponytail: dict literals + partially-const containers don't ship; add if one does.
	if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
		folded = [_fold(e, opts, targets) for e in node.elts]
		if all(c[0] for c in folded):
			vals = [c[1] for c in folded]
			ctor = tuple if isinstance(node, ast.Tuple) else set if isinstance(node, ast.Set) else list
			return True, ctor(vals)
		return False, node

	# `len(targets)` (or len of any constant) folds to an int.
	if isinstance(node, ast.Call):
		if isinstance(node.func, ast.Name) and node.func.id == 'len' and len(node.args) == 1:
			is_const, val = _fold(node.args[0], opts, targets)
			if is_const:
				return True, len(val)
		return False, node

	if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
		is_const, val = _fold(node.operand, opts, targets)
		if is_const:
			return True, (not val)
		return False, ast.UnaryOp(op=ast.Not(), operand=val)

	if isinstance(node, ast.BoolOp):
		folded = [_fold(v, opts, targets) for v in node.values]
		is_and = isinstance(node.op, ast.And)
		kept = []
		for is_const, val in folded:
			if is_const:
				truthy = bool(val)
				if is_and and not truthy:
					return True, False       # short-circuit: AND with a falsy constant
				if not is_and and truthy:
					return True, True        # short-circuit: OR with a truthy constant
				continue                     # drop AND-true / OR-false constant operands
			kept.append(val)
		if not kept:
			return True, is_and              # all operands dropped: AND->True, OR->False
		if len(kept) == 1:
			return False, kept[0]
		return False, ast.BoolOp(op=node.op, values=kept)

	if isinstance(node, ast.Compare):
		left = _fold(node.left, opts, targets)
		comps = [_fold(c, opts, targets) for c in node.comparators]
		if left[0] and all(c[0] for c in comps) and len(node.ops) == 1:
			op = _COMPARE_OPS.get(type(node.ops[0]))
			if op is not None:
				return True, bool(op(left[1], comps[0][1]))
		return False, ast.Compare(left=_as_node(left), ops=node.ops, comparators=[_as_node(c) for c in comps])

	return False, node


def _as_node(folded):
	"""Turn a (is_const, value_or_node) pair back into an AST node for unparsing."""
	is_const, val = folded
	return ast.Constant(value=val) if is_const else val


def substitute_ctx_constants(condition, ctx):
	"""Fold opts.*/targets/len(targets) runtime constants out of an extractor condition.

	Returns the residual finding-field condition (a possibly-empty string) after constant
	folding, or None when a constant-only gate makes the whole condition falsy (yield nothing).
	An empty string means the condition folded to a constant-true gate (match all of the type).
	"""
	if not condition or not str(condition).strip():
		return ''
	cond = str(condition).strip()
	if not _CTX_TOKEN_RE.search(cond):
		return cond
	tree = ast.parse(cond, mode='eval').body
	is_const, node = _fold(tree, ctx.get('opts', {}) or {}, list(ctx.get('targets', []) or []))
	if is_const:
		return None if not bool(node) else ''
	return ast.unparse(node)
