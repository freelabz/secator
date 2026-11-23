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


_CPE23_ESCAPE = re.compile(r'([^A-Za-z0-9._\-])')
_CPE23_ANY = ('', '*', '-')


def _cpe23_value(value):
	"""One CPE 2.3 attribute value: lowercased, special characters backslash-escaped."""
	value = str(value or '').strip().lower()
	if value in _CPE23_ANY:
		return value or '*'
	return _CPE23_ESCAPE.sub(r'\\\1', value)


def cpe23(cpe):
	"""A CPE 2.3 formatted string (``cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*``) for a
	CPE 2.3 or CPE 2.2 URI (``cpe:/a:vendor:product:version``, as nmap reports them), else ``None``.

	CPE 2.2 values are percent-decoded and their packed ``~`` edition is unpacked.
	"""
	if not cpe or not isinstance(cpe, str):
		return None
	c = cpe.strip().lower()
	if c.startswith('cpe:2.3:'):
		attrs = c[len('cpe:2.3:'):].split(':')
		if len(attrs) < 3:
			return None
		return 'cpe:2.3:' + ':'.join((attrs + ['*'] * 11)[:11])
	if not c.startswith('cpe:/'):
		return None
	from urllib.parse import unquote
	attrs = [unquote(a) for a in c[len('cpe:/'):].split(':')]
	if len(attrs) < 3:
		return None
	attrs = (attrs + [''] * 7)[:7]  # part, vendor, product, version, update, edition, language
	edition = attrs[5]
	extended = ['', '', '', '']  # sw_edition, target_sw, target_hw, other
	if edition.startswith('~'):  # packed: ~edition~sw_edition~target_sw~target_hw~other
		packed = (edition[1:].split('~') + [''] * 5)[:5]
		edition, extended = packed[0], packed[1:]
	values = attrs[:5] + [edition, attrs[6]] + extended
	return 'cpe:2.3:' + ':'.join([values[0]] + [_cpe23_value(v) for v in values[1:]])


def version_cpe(version, key='', cpes=None):
	"""CPE 2.3 name of this product at this version, for vulnerability lookups, or ``''``.

	A tool-reported application CPE (``cpes``) for the same product that carries a version
	wins; else one is built from the ``vendor:product`` key and ``version``. No version, no CPE:
	a versionless CPE would match every release of the product.
	"""
	if not version:
		return ''
	key = (key or '').lower()
	cpes = [cpes] if isinstance(cpes, str) else list(cpes or [])
	known = catalog()['cpes']
	for raw in cpes:
		pair = cpe_vendor_product(raw)
		c = cpe23(raw)
		if not pair or not c or c.split(':')[5] in _CPE23_ANY:
			continue
		if not key or ':'.join(pair) == key or known.get(pair) == key:
			return c
	if ':' not in key:
		return ''
	vendor, product = key.split(':', 1)
	return cpe23(f'cpe:2.3:a:{vendor}:{product}:{_cpe23_value(version)}')


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
