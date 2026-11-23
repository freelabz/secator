"""Technology identity: one normalizer, driven by the catalog in data/technologies.yaml.

Every task that emits a ``Technology`` goes through :func:`normalize_technology` (the
output type calls it), so a product reads the same whatever tool found it, and
consumers can match on a stable CPE-style ``vendor:product`` key.

Resolution order for a raw name (+ optional vendor / CPEs):
1. alias   - the cleaned name (or ``vendor name``) is a catalog alias;
2. cpe     - a CPE on the finding names a catalog entry (or, outside the catalog,
	gives the key directly);
3. fuzzy   - the name is close to exactly one entry's alias (token-set similarity
	above ``rules.fuzzy_threshold``, same numeric tokens, same vendor when
	both sides have one). Fuzzy only ever maps INTO the catalog.
"""
import os
import re
from difflib import SequenceMatcher
from functools import lru_cache

import yaml

CATALOG_PATH = os.path.join(os.path.dirname(__file__), 'data', 'technologies.yaml')

# "nginx/1.30.4", "Apache/2.4.25 (Debian)", "Apache HTTP Server:2.4.56", "IIS:10.0",
# "Microsoft-IIS/8.5", "OpenSSH_9.9p1" -> (name, version)
_EMBEDDED_VERSION = re.compile(
	r'^(?P<name>[A-Za-z][\w .+\-]*?)\s*[/:_ ]\s*v?(?P<version>\d+(?:\.\d+)+[0-9A-Za-z.+~\-]*)'
	r'(?:\s.*)?$'  # trailing "(Debian)" or a second banner component ("OpenSSL/3.0.2")
)
_BARE_VERSION = re.compile(r'^v?(\d+(?:\.\d+)+[0-9A-Za-z.+~\-]*)$')


def clean(name):
	"""Lowercase, keep parenthesised words, punctuation to spaces."""
	s = str(name or '').strip().lower()
	s = re.sub(r'\(([^)]*)\)', r' \1 ', s)
	s = re.sub(r'[^a-z0-9.+ ]+', ' ', s)
	return re.sub(r'\s+', ' ', s).strip(' .')


def split_version(raw):
	"""Split a version embedded in a product string. Returns ``(name, version or None)``.

	A bare version string (``"12.2.1.3.0"``) returns ``("", version)``.
	"""
	s = str(raw or '').strip()
	m = _BARE_VERSION.match(s)
	if m:
		return '', m.group(1)
	m = _EMBEDDED_VERSION.match(s)
	if m:
		return m.group('name').strip(), m.group('version')
	return re.sub(r'\s*\([^)]*\)\s*$', '', s), None


_CPE_ANY = ('', '*', '-')  # CPE "any" / "not applicable" values: no specific version
_CPE23_ESCAPE = re.compile(r'([^a-z0-9._\-])')
_WHITESPACE = re.compile(r'\s')


def _split_cpe23(attrs):
	"""Split CPE 2.3 attributes on ``:``, except an escaped ``\\:``; unescape each value."""
	values, cur, i = [], '', 0
	while i < len(attrs):
		ch = attrs[i]
		if ch == '\\' and i + 1 < len(attrs):
			cur += attrs[i + 1]
			i += 2
			continue
		if ch == ':':
			values.append(cur)
			cur = ''
		else:
			cur += ch
		i += 1
	values.append(cur)
	return values


def cpe_attrs(cpe):
	"""``(part, vendor, product, version)`` of a CPE 2.3 string or CPE 2.2 URI, decoded
	(2.3 backslash escapes and 2.2 percent-encoding removed, lowercased), else ``None``.

	The version is ``''`` when the CPE has none. One parser for every CPE field read.
	"""
	if not cpe or not isinstance(cpe, str):
		return None
	c = cpe.strip().lower()
	if c.startswith('cpe:2.3:'):
		values = _split_cpe23(c[len('cpe:2.3:'):])
	elif c.startswith('cpe:/'):
		from urllib.parse import unquote
		values = [unquote(v) for v in c[len('cpe:/'):].split(':')]
	else:
		return None
	if len(values) < 3:
		return None
	part, vendor, product, version = (values + [''])[:4]
	return part, vendor, product, version


def cpe_vendor_product(cpe):
	"""``(vendor, product)`` from a CPE 2.2 / 2.3 application string, else ``None``."""
	attrs = cpe_attrs(cpe)
	if not attrs:
		return None
	part, vendor, product, _ = attrs
	if part != 'a' or not vendor or not product or ' ' in vendor or ' ' in product or '*' in (vendor + product):
		return None
	return vendor, product


def cpe23(cpe):
	"""A CPE 2.3 formatted string for a CPE 2.3 string or a CPE 2.2 URI (``cpe:/a:...``, as nmap
	reports them), else ``None``.

	A CPE 2.2 URI is converted by the ``cpe`` library; a CPE 2.3 string is returned lowercased as
	is (consumers pad a short one). A CPE with no vendor / product, or with whitespace (never valid,
	e.g. one built from a free-text product name), is rejected.
	"""
	attrs = cpe_attrs(cpe)
	if not attrs or not attrs[1] or not attrs[2] or '*' in (attrs[1], attrs[2]) or _WHITESPACE.search(cpe.strip()):
		return None
	c = cpe.strip()
	if c.lower().startswith('cpe:2.3:'):
		return c.lower()
	from cpe import CPE
	try:
		return CPE(c).as_fs()
	except Exception:  # the cpe library raises NotImplementedError, IndexError, ... on malformed input
		return None


def _cpe23_escape(value):
	"""One CPE 2.3 attribute value: lowercased, special characters backslash-escaped."""
	return _CPE23_ESCAPE.sub(r'\\\1', str(value).strip().lower())


def _specific_version(version):
	"""True if ``version`` names one release and fits in a CPE (not empty / ``*`` / ``-``,
	no whitespace: ``1.0 beta`` is not a CPE version and would make the lookup find nothing)."""
	v = str(version or '').strip()
	return v not in _CPE_ANY and not _WHITESPACE.search(v)


def version_cpe(version, key='', cpes=None):
	"""CPE 2.3 name of this product at this version, for vulnerability lookups, or ``''``
	(the caller then falls back to a free-text ``product version`` lookup).

	1. A tool-reported application CPE (``cpes``) for the same product that carries a specific
	   version wins, even when it differs from ``version``: the tool chose that CPE version for
	   that product, while ``version`` is often the raw banner (nmap: version
	   ``6.6.1p1 Ubuntu 2ubuntu2.13``, CPE ``cpe:/a:openbsd:openssh:6.6.1p1``).
	2. Else one is built from the ``vendor:product`` key and ``version``, if the version is
	   specific (see :func:`_specific_version`).

	No version (empty, ``*``, ``-``), no CPE: a versionless CPE would match every release.
	"""
	if str(version or '').strip() in _CPE_ANY:
		return ''
	key = (key or '').lower()
	cpes = [cpes] if isinstance(cpes, str) else list(cpes or [])
	known = catalog()['cpes']
	for raw in cpes:
		pair = cpe_vendor_product(raw)
		if not pair or not _specific_version(cpe_attrs(raw)[3]):
			continue
		if key and ':'.join(pair) != key and known.get(pair) != key:
			continue
		c = cpe23(raw)
		if c:
			return c
	if ':' not in key or not _specific_version(version):
		return ''
	vendor, product = key.split(':', 1)
	return cpe23(f'cpe:2.3:a:{_cpe23_escape(vendor)}:{_cpe23_escape(product)}:{_cpe23_escape(version)}:*:*:*:*:*:*:*')


@lru_cache(maxsize=1)
def catalog():
	"""Load the catalog once: ``{'rules': ..., 'entries': {key: entry}, 'aliases': {alias: key}, 'cpes': {...}}``."""
	with open(CATALOG_PATH) as f:
		data = yaml.safe_load(f) or {}
	rules = data.get('rules') or {}
	rules = {
		'fuzzy_threshold': float(rules.get('fuzzy_threshold', 0.9)),
		'vendors': {clean(v) for v in rules.get('vendors') or []},
		'generic_words': {clean(v) for v in rules.get('generic_words') or []},
		'noise_words': {clean(v) for v in rules.get('noise_words') or []},
	}
	entries, aliases, cpes = {}, {}, {}
	for e in data.get('products') or []:
		key = e['key'].lower()
		vendor, product = key.split(':', 1)
		entry = {
			'key': key,
			'vendor': vendor,
			'name': e.get('name') or product.replace('_', ' '),
			'common': bool(e.get('common')),
			'requires_version': bool(e.get('requires_version')),
			'versionless_aliases': {clean(a) for a in e.get('versionless_aliases') or []},
		}
		entries[key] = entry
		names = set(e.get('aliases') or [])
		names.add(entry['name'])
		bare = product.replace('_', ' ')
		names.add(f'{vendor} {bare}')
		if clean(bare) not in rules['generic_words'] and clean(bare) not in rules['vendors']:
			names.add(bare)
		for n in names:
			aliases.setdefault(clean(n), key)
		for pair in [key] + list(e.get('cpes') or []):
			v, p = pair.lower().split(':', 1)
			cpes[(v, p)] = key
	return {'rules': rules, 'entries': entries, 'aliases': aliases, 'cpes': cpes}


def entry(key):
	"""Catalog entry for a ``vendor:product`` key, or ``None``."""
	return catalog()['entries'].get((key or '').lower())


def _strip_noise(s, noise):
	return ' '.join(t for t in s.split() if t not in noise)


def _ratio(a, b):
	ta, tb = set(a.split()), set(b.split())
	if not ta or not tb:
		return 0.0
	# Numbers are identity: "http 2" is not "http 3", "struts 1" is not "struts 2".
	if {t for t in ta if any(c.isdigit() for c in t)} != {t for t in tb if any(c.isdigit() for c in t)}:
		return 0.0
	return SequenceMatcher(None, ' '.join(sorted(ta)), ' '.join(sorted(tb))).ratio()


def lookup(name, vendor=None, cpes=None, fuzzy=True):
	"""Resolve a raw product name to a catalog key.

	Returns ``(key, method)`` with method ``alias`` / ``cpe`` / ``fuzzy``, or ``(None, None)``.
	"""
	return _lookup(str(name or ''), str(vendor or ''), tuple(cpes or ()), bool(fuzzy))


@lru_cache(maxsize=4096)
def _lookup(name, vendor, cpes, fuzzy):
	cat = catalog()
	rules, aliases = cat['rules'], cat['aliases']
	product, _ = split_version(name)
	p, v = clean(product), clean(vendor)
	candidates = []
	if p:
		if v and p == v:
			candidates.append(p)  # KEV "Apache" / "Apache": the vendor's flagship alias, if any
		elif v and not p.startswith(v + ' '):
			candidates.append(f'{v} {p}')
		candidates.append(p)
	for c in candidates:
		for form in (c, _strip_noise(c, rules['noise_words'])):
			key = aliases.get(form)
			if key and _vendor_ok(key, v):
				return key, 'alias'
	for cpe in cpes or []:
		pair = cpe_vendor_product(cpe)
		if pair and pair in cat['cpes']:
			return cat['cpes'][pair], 'cpe'
	if fuzzy and p and p not in rules['vendors'] and p not in rules['generic_words']:
		best, best_ratio, tie = None, 0.0, False
		for c in candidates:
			c = _strip_noise(c, rules['noise_words'])
			for alias, key in aliases.items():
				if not _vendor_ok(key, v):
					continue
				r = _ratio(c, alias)
				if r > best_ratio:
					best, best_ratio, tie = key, r, False
				elif r == best_ratio and key != best:
					tie = True
		if best and not tie and best_ratio >= rules['fuzzy_threshold']:
			return best, 'fuzzy'
	return None, None


def _vendor_ok(key, vendor):
	"""Does the given vendor (if any) agree with the entry? ``PHP Group`` agrees with ``php``,
	and a CPE vendor the entry is known under (``igor_sysoev`` for nginx) agrees too."""
	if not vendor:
		return True
	tokens = set(clean(vendor.replace('_', ' ')).split())
	return any(k == key and set(clean(v.replace('_', ' ')).split()) <= tokens for (v, _), k in catalog()['cpes'].items())


def normalize_technology(product, version=None, vendor=None, cpes=None):
	"""Canonical identity for a detected technology.

	Returns ``{'product', 'version', 'vendor', 'key', 'method'}``:
	``product`` is the catalog display name when known, else the raw name with any
	embedded version split off; ``key`` is the CPE ``vendor:product`` (from the catalog,
	else from an application CPE on the finding, else empty); ``method`` says how the
	key was found (``alias`` / ``cpe`` / ``fuzzy`` / ``''``).
	"""
	raw_name, embedded = split_version(product)
	cpes = [cpes] if isinstance(cpes, str) else list(cpes or [])
	key, method = lookup(product, vendor, cpes)
	if key:
		e = entry(key)
		if clean(raw_name) in e['versionless_aliases']:  # the number is not the product release
			version = embedded = None
		version = version or embedded
		return {'product': e['name'], 'version': version, 'vendor': e['vendor'], 'key': key, 'method': method}
	# Unknown product: keep its name as given ("Acme Widget (Cloud)"), only drop a split-off version.
	name = (raw_name if embedded else str(product or '').strip()) or str(product or '')
	version = version or embedded
	pair = next((cpe_vendor_product(c) for c in cpes if cpe_vendor_product(c)), None)
	if pair:
		return {'product': name, 'version': version, 'vendor': pair[0], 'key': f'{pair[0]}:{pair[1]}', 'method': 'cpe'}
	return {'product': name, 'version': version, 'vendor': clean(vendor) if vendor else '', 'key': '', 'method': ''}
