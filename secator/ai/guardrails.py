"""Permission engine for AI guardrails."""
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from secator.ai.encryption import PII_PATTERNS

# URL pattern for target detection
URL_PATTERN = re.compile(r'https?://[^\s\'"]+')

# Shell operators that chain commands
SHELL_OPERATORS = re.compile(r'\s*(?:&&|\|\||[;|])\s*')

# Read-type commands
READ_COMMANDS = frozenset({
	"cat", "grep", "head", "tail", "ls", "find", "jq", "wc", "less", "more", "file", "strings",
	"cd", "pwd", "diff", "git", "stat", "du", "df", "tree", "realpath", "readlink",
})

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
	- Basename matching for path-like values (e.g. '.env' matches '/home/user/.env')

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
		# For path-like values, also try matching against basename
		if '/' in value and '/' not in pattern:
			basename = value.rsplit('/', 1)[-1]
			if fnmatch.fnmatch(basename, pattern):
				return True
	return False


def _is_file_path(value: str) -> bool:
	"""Check if a value looks like a file path rather than a network target.

	Uses explicit path prefixes and filesystem existence checks.
	"""
	# URLs are not file paths
	if value.startswith(('http://', 'https://', 'ftp://')):
		return False
	# Explicit path prefixes are always file paths
	if value.startswith(('/', '~/', './', '../')):
		return True
	# For other values containing /, check if file or parent dir exists on disk
	if '/' in value:
		from pathlib import Path
		try:
			p = Path(value)
			if p.exists() or p.parent.exists():
				return True
		except (OSError, ValueError):
			pass
	return False


def _is_network_target(value: str) -> bool:
	"""Check if a value looks like a valid network target (IP, hostname, URL, CIDR).

	Filters out descriptive strings that aren't actual targets.
	"""
	if ' ' in value.strip():
		return False
	if value.startswith(('http://', 'https://')):
		return True
	if PII_PATTERNS["ipv4"].fullmatch(value):
		return True
	# CIDR notation (e.g. 10.0.0.0/24)
	if '/' in value and PII_PATTERNS["ipv4"].match(value.split('/')[0]):
		return True
	if PII_PATTERNS["host"].fullmatch(value):
		return True
	# host:port
	if ':' in value:
		host_part = value.rsplit(':', 1)[0]
		if PII_PATTERNS["ipv4"].fullmatch(host_part) or PII_PATTERNS["host"].fullmatch(host_part):
			return True
	return False


def detect_targets(command: str) -> List[str]:
	"""Extract target-like values (IPs, hosts, URLs) from a shell command string.

	Reuses PII_PATTERNS from secator.ai.encryption for IP and host detection.
	Excludes values that are part of file paths detected by detect_paths().

	Args:
		command: Shell command string

	Returns:
		List of detected target strings
	"""
	targets = []

	# First, detect file paths so we can exclude them from target detection
	paths = detect_paths(command)

	# Detect URLs first (most specific)
	for match in URL_PATTERN.finditer(command):
		targets.append(match.group())

	# Detect IPs (skip if part of a file path)
	for match in PII_PATTERNS["ipv4"].finditer(command):
		ip = match.group()
		if not any(ip in url for url in targets):
			if any(ip in p for p in paths):
				continue
			targets.append(ip)

	# Detect hosts (skip command names from all sub-commands)
	cmd_names = set()
	for sub_cmd in split_commands(command):
		parts = sub_cmd.split()
		if parts:
			cmd_names.add(parts[0])

	# Find quoted regions so we can skip matches inside code strings
	quoted_ranges = []
	for qm in re.finditer(r"""(?:'[^']*'|"[^"]*")""", command):
		quoted_ranges.append((qm.start(), qm.end()))

	for match in PII_PATTERNS["host"].finditer(command):
		host = match.group()
		if host in cmd_names:
			continue
		if host in targets:
			continue
		if host.endswith(('.py', '.sh', '.txt', '.json', '.yaml', '.yml', '.xml', '.csv', '.log', '.conf', '.cfg')):
			continue
		# Skip if host appears inside a detected file path
		if any(host in p for p in paths):
			continue
		# Skip if host match is inside a quoted string (likely code, not a target)
		if any(start <= match.start() and match.end() <= end for start, end in quoted_ranges):
			continue
		targets.append(host)

	return targets


def split_commands(command: str) -> List[str]:
	"""Split a compound shell command into individual sub-commands.

	Handles &&, ||, ;, and | operators while respecting single/double quotes.

	Args:
		command: Full shell command string

	Returns:
		List of individual command strings (stripped)
	"""
	# Strip quoted regions before splitting to avoid splitting inside quotes
	# Replace quoted content with placeholders, split, then restore
	placeholders = []
	cleaned = command
	for quote_match in re.finditer(r"""(?:'[^']*'|"[^"]*")""", command):
		placeholder = f"\x00QUOTED{len(placeholders)}\x00"
		placeholders.append((placeholder, quote_match.group()))
		cleaned = cleaned.replace(quote_match.group(), placeholder, 1)
	parts = [cmd.strip() for cmd in SHELL_OPERATORS.split(cleaned) if cmd.strip()]
	# Restore quoted content
	result = []
	for part in parts:
		for placeholder, original in placeholders:
			part = part.replace(placeholder, original)
		result.append(part)
	return result


def _resolve_path(path: str) -> str:
	"""Resolve a path to absolute for consistent rule matching."""
	from pathlib import Path
	try:
		return str(Path(path).expanduser().resolve())
	except (OSError, ValueError):
		return path


def detect_paths_with_access(command: str) -> List[Tuple[str, str]]:
	"""Extract file paths with access type from a shell command string.

	Handles compound commands (&&, ||, ;, |) by splitting first.
	Redirects (>, >>, 2>) are always classified as 'write'.
	Other paths are classified based on the sub-command's classification.

	Args:
		command: Shell command string

	Returns:
		List of (resolved_path, access_type) tuples where access_type is 'read' or 'write'
	"""
	seen = set()
	paths = []
	for sub_cmd in split_commands(command):
		parts = sub_cmd.split()
		if not parts:
			continue
		# Docker/podman commands run in a sandbox — only check volume mount paths
		if parts[0] in ('docker', 'podman'):
			for j, p in enumerate(parts):
				if (p in ('-v', '--volume') and j + 1 < len(parts)):
					host_path = parts[j + 1].split(':')[0]
					if _is_file_path(host_path):
						resolved = _resolve_path(host_path)
						if resolved not in seen:
							seen.add(resolved)
							paths.append((resolved, "read"))
				elif p.startswith('--mount'):
					mount_val = p.split('=', 1)[1] if '=' in p else (parts[j + 1] if j + 1 < len(parts) else '')
					for field in mount_val.split(','):
						if field.startswith(('source=', 'src=')):
							host_path = field.split('=', 1)[1]
							if _is_file_path(host_path):
								resolved = _resolve_path(host_path)
								if resolved not in seen:
									seen.add(resolved)
									paths.append((resolved, "read"))
			continue
		# Determine base access type from command classification
		cmd_name = parts[0]
		cmd_class = classify_command(cmd_name)
		base_access = "write" if cmd_class == "write" else "read"
		redirect_next = False
		for i, part in enumerate(parts):
			if i == 0:
				continue
			# Standalone redirect operator (> file, >> file, 2> file)
			if re.fullmatch(r'[012]?>{1,2}', part):
				redirect_next = True
				continue
			is_redirect = redirect_next
			redirect_next = False
			if part.startswith('-'):
				continue
			# Inline redirect prefixes (>file, 2>/dev/null, >>file)
			if re.match(r'^[012]?>{1,2}.', part):
				is_redirect = True
				part = re.sub(r'^[012]?>{1,2}', '', part)
			if not part:
				continue
			# Redirect targets are always writes; others use command classification
			if is_redirect or _is_file_path(part):
				access = "write" if is_redirect else base_access
				resolved = _resolve_path(part)
				if resolved not in seen:
					seen.add(resolved)
					paths.append((resolved, access))
	return paths


def detect_paths(command: str) -> List[str]:
	"""Extract file paths from a shell command string.

	Handles compound commands (&&, ||, ;, |) by splitting first.

	Args:
		command: Shell command string

	Returns:
		List of detected file paths
	"""
	return [path for path, _ in detect_paths_with_access(command)]


SENSITIVE_ENV_PATTERNS = re.compile(
	r'\$\{?([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z_]*)\}?',
	re.IGNORECASE
)


def detect_sensitive_env_vars(command: str) -> List[str]:
	"""Detect references to sensitive environment variables in a command.

	Matches $VAR and ${VAR} patterns where the variable name contains
	KEY, SECRET, TOKEN, PASSWORD, PASSWD, CREDENTIAL, or AUTH.

	Returns:
		List of matched variable names (e.g. ['ANTHROPIC_API_KEY'])
	"""
	return list(set(SENSITIVE_ENV_PATTERNS.findall(command)))


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
		target: The target string (IP, host, domain, or URL)

	Returns:
		List of choice dicts with label, rules, selected keys
	"""
	from urllib.parse import urlparse

	# Detect if target is a URL and extract components
	is_url = target.startswith(('http://', 'https://'))
	if is_url:
		parsed = urlparse(target)
		host = parsed.hostname or target
		port = parsed.port
		base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.path else f"{parsed.scheme}://{parsed.netloc}"
		host_port = f"{host}:{port}" if port else host

		choices = [
			{
				"label": f"Allow this URL only ({base_path})",
				"rules": [f"target({base_path}*)"],
				"selected": False,
			},
			{
				"label": f"Allow all URLs from {host_port}",
				"rules": [f"target({host})", f"target({host}:*)", f"target((http|https)://{host}:*/*)", f"target((http|https)://{host}/*)"],
				"selected": False,
			},
			{
				"label": f"Allow all URLs from {host} (any port)",
				"rules": [f"target({host})", f"target({host}:*)", f"target((http|https)://{host}:*/*)", f"target((http|https)://{host}/*)"],
				"selected": False,
			},
			{
				"label": "All of the above",
				"rules": [f"target({host})", f"target({host}:*)", f"target((http|https)://{host}:*/*)", f"target((http|https)://{host}/*)"],
				"selected": False,
			},
			{
				"label": "Deny (block this action)",
				"rules": [],
				"selected": False,
			},
		]
		# Deduplicate options 2 and 3 when there's no port
		if not port:
			choices = [choices[0], choices[1], choices[3], choices[4]]
	else:
		host_rule = f"target({target})"
		port_rule = f"target({target}:*)"
		url_rule = f"target((http|https)://{target}:*/*)"

		choices = [
			{
				"label": f"Allow {target} only",
				"rules": [host_rule],
				"selected": False,
			},
			{
				"label": f"Allow {target} (any port)",
				"rules": [host_rule, port_rule],
				"selected": False,
			},
			{
				"label": f"Allow all URLs from {target} (any port)",
				"rules": [host_rule, port_rule, url_rule, f"target((http|https)://{target}/*)"],
				"selected": False,
			},
			{
				"label": "All of the above",
				"rules": [host_rule, port_rule, url_rule, f"target((http|https)://{target}/*)"],
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
	paths: List[str] = field(default_factory=list)


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
		# Expand ~ to actual home directory in path patterns
		if "~/" in result:
			from pathlib import Path
			result = result.replace("~/", str(Path.home()) + "/")
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
			paths_with_access = detect_paths_with_access(command)
			if paths_with_access and (self._has_rules_for("read") or self._has_rules_for("write")):
				# Check each path with its correct access type
				ask_paths = []
				for path, access in paths_with_access:
					path_result = self._check_value(access, path)
					if path_result.decision == "deny":
						return PermissionResult(
							decision="deny",
							reason=path_result.reason,
							paths=[path]
						)
					if path_result.decision == "ask":
						ask_paths.append((path, access))
				if ask_paths:
					return PermissionResult(
						decision="ask",
						reason=f"Unknown {ask_paths[0][1]}(s): {ask_paths[0][0]}",
						paths=[p for p, _ in ask_paths]
					)

		# Step 4: Check for sensitive env variable references (for shell commands)
		if action_type == "shell":
			command = action.get("command", "")
			sensitive_vars = detect_sensitive_env_vars(command)
			if sensitive_vars:
				return PermissionResult(
					decision="ask",
					reason=f"References sensitive env var(s): {', '.join(sensitive_vars)}",
					targets=sensitive_vars,
				)

		if result.decision in ("allow", "ask"):
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
		"""Check if the action type is allowed/denied/ask.

		For shell commands with operators (&&, ||, ;, |), checks each sub-command.
		Returns the most restrictive result (deny > ask > allow).
		"""
		if action_type == "shell":
			command = action.get("command", "")
			sub_cmds = split_commands(command)
			most_restrictive = None
			for sub_cmd in sub_cmds:
				cmd_name = sub_cmd.split()[0] if sub_cmd.split() else ""
				result = self._check_value("shell", cmd_name)
				if result.decision == "deny":
					return result
				if result.decision == "ask":
					most_restrictive = result
				elif most_restrictive is None:
					most_restrictive = result
			return most_restrictive or PermissionResult(decision="deny", reason="Empty command")
		elif action_type in ("task", "workflow"):
			name = action.get("name", "")
			return self._check_value(action_type, name)
		elif action_type in ("query", "follow_up", "add_finding"):
			return PermissionResult(decision="allow", reason=f"{action_type} is always allowed")
		return PermissionResult(decision="deny", reason=f"Unknown action type: {action_type}")

	def _check_value(self, rule_type: str, value: str) -> PermissionResult:
		"""Check a single value. Order: deny > allow > ask > deny.

		For target rules, URL values are also checked by their host and host:port
		components so that approving 'example.com:8080' covers all URLs under it.
		"""
		# Build list of values to check (original + URL components for targets)
		values_to_check = [value]
		if rule_type == "target" and value.startswith(('http://', 'https://')):
			from urllib.parse import urlparse
			parsed = urlparse(value)
			if parsed.hostname:
				values_to_check.append(parsed.hostname)
				if parsed.port:
					values_to_check.append(f"{parsed.hostname}:{parsed.port}")

		for rt, patterns in self.rules["deny"]:
			if rt == rule_type:
				for v in values_to_check:
					if match_rule(v, patterns):
						return PermissionResult(decision="deny", reason=f"Denied by rule: {rule_type}({v})")

		for rt, patterns in self.rules["allow"]:
			if rt == rule_type:
				for v in values_to_check:
					if match_rule(v, patterns):
						return PermissionResult(decision="allow", reason=f"Allowed by rule: {rule_type}({v})")
		for rt, patterns in self.runtime_allow:
			if rt == rule_type:
				for v in values_to_check:
					if match_rule(v, patterns):
						return PermissionResult(decision="allow", reason=f"Allowed by runtime rule: {rule_type}({v})")

		for rt, patterns in self.rules["ask"]:
			if rt == rule_type:
				for v in values_to_check:
					if match_rule(v, patterns):
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
		"""Extract network targets from an action for validation.

		File paths are excluded — they are validated separately via read/write rules.
		"""
		action_type = action.get("action", "")
		if action_type == "shell":
			return detect_targets(action.get("command", ""))
		elif action_type in ("task", "workflow"):
			# Filter out file paths and non-network strings from task/workflow targets
			return [t for t in action.get("targets", []) if _is_network_target(t) and not _is_file_path(t)]
		return []

	def add_runtime_allow(self, rules: List[str]) -> None:
		"""Add rules to the runtime allow list (session-scoped)."""
		for rule_str in rules:
			rule_type, patterns = parse_rule(rule_str)
			self.runtime_allow.append((rule_type, patterns))

	def prompt_target(self, target: str, interactive: bool = True, command: str = "") -> str:
		"""Show interactive prompt for an unknown target.

		Args:
			target: The target string that needs approval
			interactive: If False, auto-deny without prompting
			command: The shell command triggering this prompt (for display)

		Returns:
			'allow' or 'deny'
		"""
		if not interactive:
			return "deny"

		choices = build_target_choices(target)
		selected_indices = self._show_target_menu(target, choices, command=command)

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

	def prompt_path(self, path: str, access_type: str = "read", interactive: bool = True, command: str = "") -> str:
		"""Show interactive prompt for a path access request.

		Args:
			path: The file path that needs approval
			access_type: 'read' or 'write'
			interactive: If False, auto-deny without prompting
			command: The shell command triggering this prompt (for display)

		Returns:
			'allow' or 'deny'
		"""
		if not interactive:
			return "deny"

		from secator.rich import InteractiveMenu

		action_label = "Read from" if access_type == "read" else "Write to"
		parent = '/'.join(path.split('/')[:-1]) if '/' in path else path
		options = [
			{"label": f"Allow {access_type}({path})"},
			{"label": f"Allow {access_type}({parent}/*)"},
			{"label": "Deny (block this action)"},
		]
		result = InteractiveMenu(
			f"{action_label} {path} requires approval.",
			options,
			description=command,
		).show()

		if result is None:
			return "deny"

		idx, _ = result
		if idx == 2:  # Deny
			return "deny"
		elif idx == 0:  # Exact path
			self.add_runtime_allow([f"{access_type}({path})"])
		elif idx == 1:  # Parent directory glob (also allow the parent itself)
			self.add_runtime_allow([f"{access_type}({parent}/*)", f"{access_type}({parent})"])
		return "allow"

	def _show_target_menu(self, target: str, choices: List[Dict], command: str = "") -> List[int]:
		"""Show interactive menu. Separated for testability.

		Args:
			target: The target being prompted about
			choices: List of choice dicts from build_target_choices
			command: The shell command triggering this prompt (for display)

		Returns:
			List of selected indices, or None if cancelled
		"""
		from secator.rich import InteractiveMenu

		options = [{"label": choice["label"]} for choice in choices]
		result = InteractiveMenu(
			f"Target {target} is not in allowed targets. Add it?",
			options,
			description=command,
		).show()

		if result is None:
			return None

		idx, _ = result
		return [idx]
