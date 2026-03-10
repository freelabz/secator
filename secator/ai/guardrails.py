"""Permission engine for AI guardrails."""
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

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


def build_target_choices(target: str) -> List[Dict]:
	"""Build multi-select choices for an unknown target.

	Args:
		target: The target string (IP, host, domain)

	Returns:
		List of choice dicts with label, rules, selected keys
	"""
	host_rule = f"target({target})"
	port_rule = f"target({target}:{{port}})"
	url_rule = f"target((http|https)://{target}:{{port}}/*)"

	choices = [
		{
			"label": f"Allow {target} only (host only)",
			"rules": [host_rule],
			"selected": False,
		},
		{
			"label": f"Allow {target}:{{port}} (host + all ports)",
			"rules": [host_rule, port_rule],
			"selected": False,
		},
		{
			"label": f"Allow (http|https)://{target}:{{port}}/* (host + URLs + all ports)",
			"rules": [host_rule, port_rule, url_rule],
			"selected": False,
		},
		{
			"label": "All of the above",
			"rules": [host_rule, port_rule, url_rule],
			"selected": False,
		},
		{
			"label": "Deny (block this action)",
			"rules": [],
			"selected": False,
		},
	]
	return choices


@dataclass
class PermissionResult:
	"""Result of a permission check."""
	decision: str  # 'allow', 'deny', 'ask'
	reason: str = ""
	targets: List[str] = field(default_factory=list)


class PermissionEngine:
	"""Evaluate AI actions against allow/deny/ask permission rules.

	Evaluation order: deny > allow > ask > default deny.
	Two-step validation: (1) action type check, (2) target/path check.
	"""

	def __init__(self, config: Dict, targets: List[str] = None, workspace: str = ""):
		self.targets = targets or []
		self.workspace = str(workspace)
		self.rules = {"allow": [], "deny": [], "ask": []}
		self.runtime_allow: List[Tuple[str, List[str]]] = []

		for category in ("allow", "deny", "ask"):
			for rule_str in config.get(category, []):
				resolved = self._resolve_variables(rule_str)
				rule_type, patterns = parse_rule(resolved)
				self.rules[category].append((rule_type, patterns))

	def _resolve_variables(self, rule: str) -> str:
		"""Replace {workspace} and {targets} variables in a rule string."""
		result = rule.replace("{workspace}", self.workspace)
		if "{targets}" in result:
			targets_str = ",".join(self.targets)
			result = result.replace("{targets}", targets_str)
		return result

	def check_action(self, action: Dict) -> PermissionResult:
		"""Validate an action against permission rules (two-step)."""
		action_type = action.get("action", "")

		# Step 1: Check action itself
		result = self._check_action_type(action_type, action)
		if result.decision == "deny":
			return result

		# Step 2: Check targets (only if target rules are configured)
		targets_to_check = self._extract_targets(action)
		if targets_to_check and self._has_rules_for("target"):
			target_result = self._check_values("target", targets_to_check)
			if target_result.decision == "deny":
				return target_result
			if target_result.decision == "ask":
				return PermissionResult(
					decision="ask",
					reason=target_result.reason,
					targets=target_result.targets
				)

		# Step 3: Check paths (for shell commands)
		if action_type == "shell":
			command = action.get("command", "")
			paths = detect_paths(command)
			if paths and (self._has_rules_for("read") or self._has_rules_for("write")):
				cmd_name = command.split()[0] if command.split() else ""
				cmd_class = classify_command(cmd_name)
				if cmd_class == "read":
					path_result = self._check_values("read", paths)
				elif cmd_class == "write":
					path_result = self._check_values("write", paths)
				else:
					path_result = self._check_values("read", paths)
				if path_result.decision != "allow":
					return path_result

		if result.decision == "allow":
			return result

		return PermissionResult(decision="deny", reason=f"No matching rule for {action_type}")

	def _has_rules_for(self, rule_type: str) -> bool:
		"""Check if any rules exist for the given rule type."""
		for category in ("allow", "deny", "ask"):
			for rt, _ in self.rules[category]:
				if rt == rule_type:
					return True
		return any(rt == rule_type for rt, _ in self.runtime_allow)

	def _check_action_type(self, action_type: str, action: Dict) -> PermissionResult:
		"""Check if the action type is allowed/denied/ask."""
		if action_type == "shell":
			command = action.get("command", "")
			cmd_name = command.split()[0] if command.split() else ""
			return self._check_value("shell", cmd_name)
		elif action_type in ("task", "workflow"):
			name = action.get("name", "")
			return self._check_value(action_type, name)
		elif action_type in ("query", "follow_up", "add_finding"):
			return PermissionResult(decision="allow", reason=f"{action_type} is always allowed")
		return PermissionResult(decision="deny", reason=f"Unknown action type: {action_type}")

	def _check_value(self, rule_type: str, value: str) -> PermissionResult:
		"""Check a single value. Order: deny > allow > ask > deny."""
		for rt, patterns in self.rules["deny"]:
			if rt == rule_type and match_rule(value, patterns):
				return PermissionResult(decision="deny", reason=f"Denied by rule: {rule_type}({value})")

		for rt, patterns in self.rules["allow"]:
			if rt == rule_type and match_rule(value, patterns):
				return PermissionResult(decision="allow", reason=f"Allowed by rule: {rule_type}({value})")
		for rt, patterns in self.runtime_allow:
			if rt == rule_type and match_rule(value, patterns):
				return PermissionResult(decision="allow", reason=f"Allowed by runtime rule: {rule_type}({value})")

		for rt, patterns in self.rules["ask"]:
			if rt == rule_type and match_rule(value, patterns):
				return PermissionResult(decision="ask", reason=f"Ask for: {rule_type}({value})")

		return PermissionResult(decision="deny", reason=f"No rule for {rule_type}({value})")

	def _check_values(self, rule_type: str, values: List[str]) -> PermissionResult:
		"""Check multiple values, return the most restrictive result."""
		ask_targets = []
		for value in values:
			result = self._check_value(rule_type, value)
			if result.decision == "deny":
				return result
			if result.decision == "ask":
				ask_targets.append(value)
		if ask_targets:
			return PermissionResult(
				decision="ask",
				reason=f"Unknown {rule_type}(s): {', '.join(ask_targets)}",
				targets=ask_targets
			)
		return PermissionResult(decision="allow")

	def _extract_targets(self, action: Dict) -> List[str]:
		"""Extract targets from an action for validation."""
		action_type = action.get("action", "")
		if action_type == "shell":
			return detect_targets(action.get("command", ""))
		elif action_type in ("task", "workflow"):
			return action.get("targets", [])
		return []

	def add_runtime_allow(self, rules: List[str]) -> None:
		"""Add rules to the runtime allow list (session-scoped)."""
		for rule_str in rules:
			rule_type, patterns = parse_rule(rule_str)
			self.runtime_allow.append((rule_type, patterns))

	def prompt_target(self, target: str, interactive: bool = True) -> str:
		"""Show interactive prompt for an unknown target.

		Args:
			target: The target string that needs approval
			interactive: If False, auto-deny without prompting

		Returns:
			'allow' or 'deny'
		"""
		if not interactive:
			return "deny"

		choices = build_target_choices(target)
		selected_indices = self._show_target_menu(target, choices)

		if selected_indices is None:
			return "deny"

		all_rules = []
		for idx in selected_indices:
			if idx < len(choices):
				choice = choices[idx]
				if not choice["rules"]:  # Deny choice
					return "deny"
				all_rules.extend(choice["rules"])

		if not all_rules:
			return "deny"

		unique_rules = list(dict.fromkeys(all_rules))
		self.add_runtime_allow(unique_rules)
		return "allow"

	def _show_target_menu(self, target: str, choices: List[Dict]) -> List[int]:
		"""Show interactive menu. Separated for testability.

		Args:
			target: The target being prompted about
			choices: List of choice dicts from build_target_choices

		Returns:
			List of selected indices, or None if cancelled
		"""
		from secator.rich import console, InteractiveMenu

		console.print(f"\n[bold yellow]Target [cyan]{target}[/cyan] is not in allowed targets. Add it?[/]\n")

		options = [{"label": choice["label"]} for choice in choices]
		result = InteractiveMenu(f"Select permissions for {target}", options).show()

		if result is None:
			return None

		idx, _ = result
		return [idx]
