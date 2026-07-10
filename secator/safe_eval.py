"""Restricted AST evaluator for the workflow/scan/tree `if:`/`condition:` DSL.

Only a small, explicit grammar is accepted (attribute access, comparisons,
boolean ops, `in`, a fixed set of string/dict methods, and whitelisted
functions like `len`/`re_match`). Anything outside that grammar is rejected
before evaluation, so the accepted condition language is explicit rather than
"whatever Python's eval() happens to allow".
"""

import ast

ALLOWED_METHODS = {"startswith", "endswith", "lower", "upper", "strip", "lstrip", "rstrip", "get"}

_ALLOWED_NODES = (
	ast.Expression,
	ast.BoolOp, ast.And, ast.Or,
	ast.UnaryOp, ast.Not,
	ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
	ast.Name, ast.Load,
	ast.Attribute,
	ast.Constant,
	ast.List, ast.Tuple,
	ast.Call, ast.keyword,
)


def _validate(node, names, funcs):
	if not isinstance(node, _ALLOWED_NODES):
		raise ValueError(f"unsupported expression: {ast.dump(node)}")

	if isinstance(node, ast.Attribute):
		if "__" in node.attr:
			raise ValueError(f"unsupported expression: attribute access to {node.attr!r}")
		_validate(node.value, names, funcs)

	elif isinstance(node, ast.Name):
		if node.id not in names and node.id not in funcs:
			raise ValueError(f"unsupported expression: unknown name {node.id!r}")

	elif isinstance(node, ast.Call):
		func = node.func
		if isinstance(func, ast.Name) and func.id in funcs:
			pass
		elif isinstance(func, ast.Attribute) and func.attr in ALLOWED_METHODS and "__" not in func.attr:
			_validate(func.value, names, funcs)
		else:
			raise ValueError(f"unsupported expression: call to {ast.dump(func)}")
		for arg in node.args:
			if isinstance(arg, ast.Starred):
				raise ValueError("unsupported expression: starred argument")
			_validate(arg, names, funcs)
		for kw in node.keywords:
			if kw.arg is None:  # **kwargs
				raise ValueError("unsupported expression: **kwargs")
			_validate(kw.value, names, funcs)

	else:
		for child in ast.iter_child_nodes(node):
			_validate(child, names, funcs)


def safe_eval_condition(expr, names, funcs=None):
	"""Evaluate a condition expression restricted to the condition DSL grammar.

	Args:
		expr (str): condition expression, e.g. "item.type == 'url' and not opts.passive".
		names (dict): variables available to the expression (e.g. item, opts, targets).
		funcs (dict): whitelisted callables available to the expression (e.g. len, re_match).

	Returns:
		The result of evaluating `expr`.

	Raises:
		ValueError: if `expr` contains anything outside the allowed grammar.
	"""
	funcs = funcs or {}
	tree = ast.parse(expr, mode='eval')
	_validate(tree, names, funcs)
	return eval(compile(tree, "<condition>", "eval"), {"__builtins__": {}}, {**names, **funcs})  # noqa: S307


def demo():
	assert safe_eval_condition("a == 1", {"a": 1}) is True
	assert safe_eval_condition("a.startswith('x')", {"a": "xyz"}) is True
	assert safe_eval_condition("len(items) == 0", {"items": []}, {"len": len}) is True
	try:
		safe_eval_condition("a.__class__", {"a": 1})
		raise AssertionError("expected ValueError for dunder attribute access")
	except ValueError:
		pass
	try:
		safe_eval_condition("open('/etc/passwd')", {})
		raise AssertionError("expected ValueError for disallowed call")
	except ValueError:
		pass
	print("safe_eval self-check OK")


if __name__ == "__main__":
	demo()
