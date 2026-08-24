"""Match a target against ``in_scope`` / ``out_of_scope`` allow/deny lists.

Pure, no network I/O (parsing via ``classify_target(resolve=False)``). Only
network targets (ip/cidr/host/host:port/url) are checked; non-network items
(email, username, path, ...) are always kept. Deny wins; empty ``in_scope`` =
allow-all (subject to deny).

Entry kinds: IP/CIDR (``ipaddress`` containment, v4+v6, ``subnet_of``); exact
host; ``*.acme.com`` wildcard (sub-domains only, not the apex); ``re.fullmatch``-
anchored regex (``acme\\.com`` never matches ``evil-acme.com.x``). Regexes are
scope entries, never targets.
"""

import ipaddress
import logging
import re

from secator.definitions import CIDR_RANGE, IP
from secator.utils import (
	NETWORK_TYPES,
	_is_ip_literal,
	_target_host,
	canonicalize_target,
	classify_target,
)

logger = logging.getLogger(__name__)

# Regex scope entries are AUTHOR-controlled (platform mandate config), but the
# TARGET they match is attacker-controlled (a discovered subdomain), so a
# vulnerable author pattern + crafted target is a ReDoS vector. Python's `re`
# has no match timeout, so we mitigate at COMPILE time: reject patterns with
# nested quantifiers (the classic catastrophic-backtracking shape) and cap the
# length of the string we ever feed to a regex. Both are best-effort.
_MAX_REGEX_INPUT = 2048
# Heuristic: a quantified group whose body also contains a quantifier -> (a+)+,
# (a*)*, (a+)*b, ... Best-effort (single-level groups); flagged in the report.
_NESTED_QUANTIFIER = re.compile(r'\([^()]*[+*?][^()]*\)[+*]')

# Regex metacharacters that mark an entry as a regex rather than a structural
# host/wildcard/CIDR. `.` and `*` are excluded: they are the ordinary furniture
# of hostnames (`app.acme.com`) and wildcards (`*.acme.com`).
_REGEX_META = set('[](){}|+?^$\\')

# Compiled-regex cache. Value is a compiled pattern, or None for an entry that
# failed to compile / was rejected as catastrophic (-> treated as non-matching).
_regex_cache = {}


def _compile_entry(entry):
	"""Compile a regex scope entry once, fail-safe. Returns a compiled pattern or None.

	None means the entry never matches. On a bad/catastrophic pattern we log a
	warning: a broken ALLOW entry silently narrows scope; a broken DENY entry
	silently stops excluding -- see the fail-safe note in the module docstring
	and the PR report. We deliberately do NOT fail a broken deny closed (deny
	everything), because a single mistyped exclusion would otherwise DoS the
	whole scan; the (non-empty) allow-list remains the primary boundary.
	"""
	if entry in _regex_cache:
		return _regex_cache[entry]
	compiled = None
	if _NESTED_QUANTIFIER.search(entry):
		logger.warning('scope: skipping regex entry with catastrophic (ReDoS) pattern: %r', entry)
	else:
		try:
			compiled = re.compile(entry)
		except re.error as e:
			logger.warning('scope: skipping un-compilable regex entry %r: %s', entry, e)
	_regex_cache[entry] = compiled
	return compiled


class _Shape:
	"""Parsed target: exactly one of net / ip / host is set. `canonical` is the
	full canonical target string (what regex entries fullmatch against)."""
	__slots__ = ('net', 'ip', 'host', 'canonical')

	def __init__(self, net=None, ip=None, host=None, canonical=''):
		self.net = net
		self.ip = ip
		self.host = host
		self.canonical = canonical


def _target_shape(target):
	"""Parse a target into a `_Shape`, or return None if it is not a NETWORK target.

	Reuses PR1's single-source classifier for type detection and canonicalization
	(alternate IPv4 encodings, IDNA, bracketed IPv6, ...) -- NO IP/host parsing is
	re-implemented here. `resolve=False` keeps this pure (no DNS).
	"""
	info = classify_target(target, resolve=False)
	if info.type not in NETWORK_TYPES:
		return None
	canonical = canonicalize_target(target)
	if info.type == CIDR_RANGE:
		return _Shape(net=ipaddress.ip_network(canonical, strict=False), canonical=canonical)
	if info.type == IP and _is_ip_literal(canonical):
		return _Shape(ip=ipaddress.ip_address(canonical), canonical=canonical)
	# URL / HOST / HOST_PORT (and `localhost`, typed IP but not a real IP literal):
	# pull the host out (strips scheme / port / path).
	host = _target_host(canonical, info.type)
	if _is_ip_literal(host):
		# IP literal hiding in a url / host:port (8.8.8.8:443, http://8.8.8.8/) --
		# match it by network containment, never as a hostname string.
		return _Shape(ip=ipaddress.ip_address(host), canonical=canonical)
	return _Shape(host=host.lower().rstrip('.'), canonical=canonical)


def _entry_net(entry):
	"""Parse a scope entry as an IP or CIDR network, or None. A bare IP -> /32 or /128."""
	try:
		return ipaddress.ip_network(entry, strict=False)
	except ValueError:
		return None


def _shape_matches_entry(shape, entry):
	"""True if the parsed target `shape` is covered by a single scope `entry`."""
	entry = entry.strip()
	if not entry:
		return False

	# Wildcard: *.acme.com covers sub-domains, NOT the apex.
	if entry.startswith('*.'):
		if shape.host is None:
			return False
		base = entry[2:].lower().rstrip('.')
		return bool(base) and shape.host.endswith('.' + base)

	# IP / CIDR entry: pure network containment (v4 and v6).
	entry_net = _entry_net(entry)
	if entry_net is not None:
		if shape.net is not None:
			return shape.net.version == entry_net.version and shape.net.subnet_of(entry_net)
		if shape.ip is not None:
			return shape.ip.version == entry_net.version and shape.ip in entry_net
		return False  # hostname target can't be inside an IP network

	# Regex entry: FULLMATCH-anchored (both ends), ReDoS-guarded.
	if any(c in _REGEX_META for c in entry):
		compiled = _compile_entry(entry)
		if compiled is None or len(shape.canonical) > _MAX_REGEX_INPUT:
			return False
		return compiled.fullmatch(shape.canonical) is not None

	# Exact host entry: canonical-host equality.
	if shape.host is None:
		return False
	return shape.host == entry.lower().rstrip('.')


def target_in_scope(target, scope):
	"""True if a NETWORK target string is covered by any entry in `scope`.

	Non-network targets return False here (the keep decision for them lives in
	``host_in_scope``, which never routes them through this predicate).
	"""
	shape = _target_shape(target)
	if shape is None:
		return False
	return any(_shape_matches_entry(shape, e) for e in scope)


def as_scope_list(val):
	"""Coerce a scope run-option into a list of entries.

	Accepts ``None`` (-> ``[]``), a comma-separated string (CLI form), or a list.
	"""
	if not val:
		return []
	if isinstance(val, str):
		return [v.strip() for v in val.split(',') if v.strip()]
	return [str(v).strip() for v in val if str(v).strip()]


def host_in_scope(target, in_scope=None, out_of_scope=None):
	"""Allow/deny scope decision for a single target. Deny wins.

	- Non-network target (email / username / path / ...) -> True (never scoped).
	- ``out_of_scope`` match                             -> False (deny wins over allow).
	- non-empty ``in_scope``                             -> target must match an allow entry.
	- empty ``in_scope``                                 -> allow-all (subject to deny).
	"""
	in_scope = as_scope_list(in_scope)
	out_of_scope = as_scope_list(out_of_scope)
	if not in_scope and not out_of_scope:
		return True
	shape = _target_shape(target)
	if shape is None:
		return True  # non-network item: scope is network-only, always kept
	if out_of_scope and any(_shape_matches_entry(shape, e) for e in out_of_scope):
		return False
	if in_scope:
		return any(_shape_matches_entry(shape, e) for e in in_scope)
	return True
