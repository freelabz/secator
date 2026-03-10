"""Permission engine for AI guardrails."""
import fnmatch
import re
from typing import List, Tuple

from secator.ai.encryption import PII_PATTERNS

# URL pattern for target detection
URL_PATTERN = re.compile(r'https?://[^\s\'"]+')

# Read-type commands
READ_COMMANDS = frozenset({"cat", "grep", "head", "tail", "ls", "find", "jq", "wc", "less", "more", "file", "strings"})

# Write-type commands
WRITE_COMMANDS = frozenset({"tee", "cp", "mv", "sed", "awk", "dd", "install", "mkdir", "touch", "chmod", "chown"})

# Execute-type commands
EXECUTE_COMMANDS = frozenset({"python", "python3", "bash", "sh", "node", "ruby", "perl", "gcc", "g++", "make", "go"})


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


def detect_targets(command: str) -> List[str]:
	"""Extract target-like values (IPs, hosts, URLs) from a shell command string.

	Reuses PII_PATTERNS from secator.ai.encryption for IP and host detection.

	Args:
		command: Shell command string

	Returns:
		List of detected target strings
	"""
	targets = []

	# Detect URLs first (most specific)
	for match in URL_PATTERN.finditer(command):
		targets.append(match.group())

	# Detect IPs
	for match in PII_PATTERNS["ipv4"].finditer(command):
		ip = match.group()
		if not any(ip in url for url in targets):
			targets.append(ip)

	# Detect hosts
	cmd_parts = command.split()
	cmd_name = cmd_parts[0] if cmd_parts else ""
	for match in PII_PATTERNS["host"].finditer(command):
		host = match.group()
		if host == cmd_name:
			continue
		if host in targets:
			continue
		if host.endswith(('.py', '.sh', '.txt', '.json', '.yaml', '.yml', '.xml', '.csv', '.log', '.conf', '.cfg')):
			continue
		targets.append(host)

	return targets


def detect_paths(command: str) -> List[str]:
	"""Extract file paths from a shell command string.

	Args:
		command: Shell command string

	Returns:
		List of detected file paths
	"""
	paths = []
	parts = command.split()

	for i, part in enumerate(parts):
		if i == 0:
			continue
		if part.startswith('-'):
			continue
		if part.startswith('/') or part.startswith('~/') or part.startswith('./') or part.startswith('../'):
			paths.append(part)

	return paths


def classify_command(cmd_name: str) -> str:
	"""Classify a command as read, write, execute, or other.

	Args:
		cmd_name: The command name (first token)

	Returns:
		One of: 'read', 'write', 'execute', 'other'
	"""
	base = cmd_name.rsplit('/', 1)[-1]
	if base in READ_COMMANDS:
		return "read"
	if base in WRITE_COMMANDS:
		return "write"
	if base in EXECUTE_COMMANDS:
		return "execute"
	return "other"
