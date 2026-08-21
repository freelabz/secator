"""Generic target-scope allow/deny filtering.

secator core has NO concept of mandates, bug-bounty programs, or any platform
authorization model — and it must not. This module is a neutral host/target
scope matcher: given a target string and plain scope entries (a host, a
``*.wildcard``, a CIDR, or a regex), decide whether the target is in scope.

The platform (secator-api) derives the effective authorized scope from whatever
authorization model it uses and passes it in as generic ``in_scope`` /
``out_of_scope`` run-options. Core then enforces that allow-list on EVERY target
it acts on — including subdomains discovered mid-scan (subdomain_recon output
fed into host_recon) — closing the scope-escape where dynamically-discovered
targets were never checked against the run's authorized scope.

The matching rules here intentionally mirror the platform's own scope matcher so
a target that the ingress gate would reject is dropped identically mid-scan. The
two copies share no code (separate repos, and core stays authorization-agnostic
by design); keep the semantics in sync — see ``test_scope.py`` for the shared
vectors.
"""

import ipaddress
import re
from urllib.parse import urlparse


def _looks_like_regex(entry: str) -> bool:
	"""Heuristic: does this scope entry use regex metacharacters?

	A plain host/wildcard/CIDR entry (``app.acme.com``, ``*.acme.com``,
	``1.2.3.0/24``) is matched with the structural host/network logic below. An
	entry containing regex metacharacters other than the ``*``/``.`` used by
	wildcards/hostnames is treated as a regex and matched against the raw target.
	"""
	regex_meta = set("[](){}|+?^$\\")
	return any(c in regex_meta for c in entry)


def _entry_matches_regex(target: str, entry: str) -> bool:
	"""True if `entry` is a regex that matches the raw target string."""
	try:
		return re.search(entry, target) is not None
	except re.error:
		return False


def _host_of(target: str) -> str:
	"""Extract a comparable host from a target string (url/host/domain)."""
	t = target.strip()
	if "://" in t:
		return urlparse(t).hostname or ""
	return t.split("/")[0].split(":")[0]


def _as_network(value: str):
	try:
		return ipaddress.ip_network(value, strict=False)
	except ValueError:
		return None


def target_in_scope(target: str, scope: list) -> bool:
	"""True if target string is covered by any scope entry.

	Each entry is treated as a single-or-regex value: a plain host/wildcard/CIDR
	is matched structurally (exact host, ``*.wildcard`` subdomain, IP-in-CIDR,
	CIDR-subnet-of), while an entry containing regex metacharacters is matched as
	a regex against the raw target string.
	"""
	target = target.strip()
	# Regex entries: match against the raw target first.
	for entry in scope:
		entry = entry.strip()
		if _looks_like_regex(entry) and _entry_matches_regex(target, entry):
			return True
	target_net = _as_network(target) if ("/" in target or target.replace(".", "").isdigit()) else None
	# IP/CIDR matching
	for entry in scope:
		entry = entry.strip()
		if _looks_like_regex(entry):
			continue
		entry_net = _as_network(entry)
		if entry_net is not None:
			if target_net is not None:
				if target_net.subnet_of(entry_net):
					return True
			else:
				host = _host_of(target)
				try:
					if ipaddress.ip_address(host) in entry_net:
						return True
				except ValueError:
					pass
	# A pure IP/CIDR target only matches via network containment (handled above);
	# never fall through to hostname matching, otherwise "1.2.3.0/24" and
	# "1.2.3.0/25" would match as equal hostnames ("1.2.3.0").
	if target_net is not None:
		return False
	# hostname matching
	host = _host_of(target).lower().rstrip(".")
	if not host:
		return False
	for entry in scope:
		if _looks_like_regex(entry):
			continue
		e = _host_of(entry).lower().rstrip(".")
		if e.startswith("*."):
			base = e[2:]
			if host.endswith("." + base):
				return True
		elif host == e:
			return True
	return False


def as_scope_list(val):
	"""Coerce a scope run-option into a list of entries.

	Accepts ``None`` (-> ``[]``), a comma-separated string (CLI form), or a list.
	"""
	if not val:
		return []
	if isinstance(val, str):
		return [v.strip() for v in val.split(",") if v.strip()]
	return [str(v).strip() for v in val if str(v).strip()]


def host_in_scope(target: str, in_scope=None, out_of_scope=None) -> bool:
	"""Allow/deny decision for a single target. Deny wins.

	- ``out_of_scope`` match  -> out (deny wins over allow).
	- non-empty ``in_scope``  -> target must match an allow entry.
	- empty ``in_scope``      -> allow-all (subject to deny).
	"""
	in_scope = as_scope_list(in_scope)
	out_of_scope = as_scope_list(out_of_scope)
	if out_of_scope and target_in_scope(target, out_of_scope):
		return False
	if in_scope:
		return target_in_scope(target, in_scope)
	return True
