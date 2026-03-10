"""Permission engine for AI guardrails."""
import fnmatch
import re
from typing import List, Tuple


def parse_rule(rule: str) -> Tuple[str, List[str]]:
	"""Parse a rule string like 'target(10.0.0.1,example.com)' into (type, patterns).

	Args:
		rule: Rule string in format 'type(value1,value2,...)'

	Returns:
		Tuple of (rule_type, list_of_patterns)
	"""
	match = re.match(r'^(\w+)\((.+)\)$', rule)
	if not match:
		return ("unknown", [rule])
	rule_type = match.group(1)
	values = [v.strip() for v in match.group(2).split(',')]
	return rule_type, values


def match_rule(value: str, patterns: List[str]) -> bool:
	"""Check if a value matches any of the given patterns.

	Supports:
	- Exact match
	- Wildcard '*' (matches everything)
	- Glob patterns (fnmatch)
	- {port} variable (matches :\\d+)

	Args:
		value: The value to check
		patterns: List of patterns to match against

	Returns:
		True if value matches any pattern
	"""
	for pattern in patterns:
		if pattern == "*":
			return True
		if "{port}" in pattern:
			regex_pattern = re.escape(pattern).replace(r"\{port\}", r"\d+")
			if re.fullmatch(regex_pattern, value):
				return True
			continue
		if fnmatch.fnmatch(value, pattern):
			return True
	return False
