"""CPE helpers: parse, convert and compare CPE 2.2 URIs / CPE 2.3 formatted strings.

One escape-aware parser (:func:`cpe_attrs`) for every CPE field read; :func:`cpe23` converts a
CPE 2.2 URI (as nmap reports them) with the ``cpe`` library; :func:`version_cpe` builds the
CPE 2.3 name of a catalog product at a version for vulnerability lookups.
"""
import re

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
	from secator.technology import catalog  # lazy: secator.technology imports this module
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


def create_cpe_string(product_name, version):
	"""
	Generate a CPE string for a given product and version.

	Args:
		product_name (str): The name of the product.
		version (str): The version of the product.

	Returns:
		str: A CPE string formatted according to the CPE 2.3 specification.
	"""
	cpe_version = '2.3'  # CPE Specification version
	part = 'a'  # 'a' for application
	vendor = product_name.lower()  # Vendor name, using product name
	product = product_name.lower()  # Product name
	version = version  # Product version
	cpe_string = f'cpe:{cpe_version}:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*'
	return cpe_string


def match_cpes(fs1, fs2):
	"""Check if two CPEs match. Partial matches consisting of <vendor>:<product>:<version> are considered a match.

	Args:
		fs1 (str): Format string 1.
		fs2 (str): Format string 2.

	Returns:
		bool: True if the two CPEs match, False otherwise.
	"""
	if fs1 == fs2:
		return True
	attrs1, attrs2 = cpe_attrs(fs1), cpe_attrs(fs2)  # escape-aware, tolerates a short CPE
	return bool(attrs1 and attrs2) and attrs1[1:4] == attrs2[1:4]
