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
	r'(?:\s*\(.*\))?\s*$'
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


def cpe_vendor_product(cpe):
	"""``(vendor, product)`` from a CPE 2.2 / 2.3 application string, else ``None``."""
	if not cpe or not isinstance(cpe, str):
		return None
	c = cpe.strip().lower()
	if c.startswith('cpe:2.3:'):
		parts = c.split(':')
		part, vendor, product = (parts[2], parts[3], parts[4]) if len(parts) >= 5 else ('', '', '')
	elif c.startswith('cpe:/'):
		parts = c[5:].split(':')
		part, vendor, product = (parts[0], parts[1], parts[2]) if len(parts) >= 3 else ('', '', '')
	else:
		return None
	if part != 'a' or not vendor or not product or ' ' in vendor or ' ' in product or '*' in (vendor + product):
		return None
	return vendor, product


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
	tokens = set(vendor.split())
	return any(k == key and v in tokens for (v, _), k in catalog()['cpes'].items())


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
		if clean(raw_name) in e['versionless_aliases']:
			embedded = None
		version = version or embedded
		return {'product': e['name'], 'version': version, 'vendor': e['vendor'], 'key': key, 'method': method}
	version = version or embedded
	pair = next((cpe_vendor_product(c) for c in cpes if cpe_vendor_product(c)), None)
	if pair:
		return {'product': raw_name or str(product or ''), 'version': version, 'vendor': pair[0],
				'key': f'{pair[0]}:{pair[1]}', 'method': 'cpe'}
	return {'product': raw_name or str(product or ''), 'version': version, 'vendor': clean(vendor) if vendor else '',
			'key': '', 'method': ''}
