"""Fetch a single web page and return its readable text — for the AI ``fetch_url`` tool.

This lets the agent READ a specific public page it already knows about (a HackTricks
technique, a vendor advisory, a Debian security-tracker page, a blog post on a fresh CVE),
as opposed to ``web_search`` which discovers pages.

SECURITY — this must never widen our own attack surface (SSRF). The agent picks the URL, so
before every request (and every redirect hop) we enforce, in :func:`is_safe_public_url`:

- scheme is ``http`` / ``https`` only (no ``file:``, ``gopher:``, ``ftp:``, ``dict:`` …);
- the host does not resolve to a private, loopback, link-local, or otherwise reserved
address — every resolved A/AAAA record must be a global address, which also blocks the
cloud metadata endpoint (169.254.169.254) and DNS-rebinding to an internal host.

Redirects are followed manually so each hop is re-validated; cookies/auth are never sent;
the response is size-capped and only text-like content types are read. All failures are
soft — a blocked or failed fetch returns an error string, never an exception that aborts
the AI loop.
"""

import html
import ipaddress
import re
import socket
from urllib.parse import urlparse, urljoin

from secator.requests import requests
from secator.utils import debug

_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
_TIMEOUT = 20
_MAX_BYTES = 2_000_000        # cap the raw download
_MAX_CHARS_DEFAULT = 20_000   # cap the extracted text handed to the model
_MAX_REDIRECTS = 5
_TEXT_CT = ('text/', 'application/json', 'application/xml', 'application/xhtml', '+json', '+xml', 'application/rss', 'application/atom')  # noqa: E501

_SCRIPT_STYLE_RE = re.compile(r'<(script|style|noscript|template|svg)\b[^>]*>.*?</\1>', re.I | re.S)
_TAG_RE = re.compile(r'<[^>]+>')
_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
_WS_RE = re.compile(r'[ \t\r\f\v]+')
_MULTINL_RE = re.compile(r'\n{3,}')


def _host_is_public(host):
	"""True iff every address ``host`` resolves to is a global (public) IP.

	A hostname with any private/loopback/link-local/reserved record is rejected (fail-closed):
	that closes SSRF to internal services, the cloud metadata IP (link-local 169.254.0.0/16),
	and DNS-rebinding tricks. A host that can't be resolved is rejected too."""
	if not host:
		return False
	# A bracketed/plain IP literal: check it directly.
	literal = host[1:-1] if host.startswith('[') and host.endswith(']') else host
	try:
		ip = ipaddress.ip_address(literal)
		return _ip_is_public(ip)
	except ValueError:
		pass
	try:
		infos = socket.getaddrinfo(host, None)
	except (socket.gaierror, UnicodeError, OSError):
		return False
	addrs = {info[4][0] for info in infos}
	if not addrs:
		return False
	for a in addrs:
		try:
			if not _ip_is_public(ipaddress.ip_address(a.split('%')[0])):
				return False
		except ValueError:
			return False
	return True


def _ip_is_public(ip):
	"""Reject every non-global range: private, loopback, link-local, multicast, reserved,
	unspecified — and IPv4-mapped/6to4/Teredo wrappers around a private v4."""
	if isinstance(ip, ipaddress.IPv6Address):
		if ip.ipv4_mapped is not None:
			return _ip_is_public(ip.ipv4_mapped)
		sixtofour = getattr(ip, 'sixtofour', None)
		if sixtofour is not None:
			return _ip_is_public(sixtofour)
	return not (
		ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
		or ip.is_reserved or ip.is_unspecified
	)


def is_safe_public_url(url):
	"""Return (ok, reason). ok=True only for an http(s) URL whose host resolves entirely to
	public addresses. reason explains a rejection (for the model)."""
	try:
		p = urlparse(url)
	except ValueError:
		return False, 'unparseable URL'
	if p.scheme not in ('http', 'https'):
		return False, f"scheme {p.scheme or '(none)'!r} not allowed (http/https only)"
	if not p.hostname:
		return False, 'URL has no host'
	if not _host_is_public(p.hostname):
		return False, f'host {p.hostname} is not a public address (blocked to prevent SSRF)'
	return True, ''


def _extract_text(body, content_type):
	"""Turn an HTML/text body into readable plain text (+ a title for HTML)."""
	title = ''
	if 'html' in content_type or ('<html' in body[:2000].lower()):
		m = _TITLE_RE.search(body)
		if m:
			title = _WS_RE.sub(' ', re.sub(_TAG_RE, '', html.unescape(m.group(1)))).strip()
		body = _SCRIPT_STYLE_RE.sub(' ', body)
		body = _TAG_RE.sub(' ', body)
		body = html.unescape(body)
	# Normalize whitespace: collapse runs of spaces/tabs, keep paragraph breaks, trim runs of blank lines.
	lines = [_WS_RE.sub(' ', ln).strip() for ln in body.splitlines()]
	text = '\n'.join(ln for ln in lines if ln != '' or True)  # keep single blanks
	text = _MULTINL_RE.sub('\n\n', text).strip()
	return title, text


def fetch_url(url, max_chars=_MAX_CHARS_DEFAULT, timeout=_TIMEOUT):
	"""Fetch one public page and return (result, error).

	result on success: {url (final), status, content_type, title, text, truncated}.
	error is a string on failure (SSRF block, non-text body, network error, …); result is None then.
	Never raises.
	"""
	try:
		max_chars = int(max_chars)
	except (TypeError, ValueError):
		max_chars = _MAX_CHARS_DEFAULT
	max_chars = max(200, min(max_chars, 200_000))

	current = str(url or '').strip()
	if not current:
		return None, 'fetch_url requires a non-empty url'

	for _hop in range(_MAX_REDIRECTS + 1):
		ok, reason = is_safe_public_url(current)
		if not ok:
			return None, f'refused to fetch {current!r}: {reason}'
		try:
			# allow_redirects=False so we re-validate every hop against the SSRF guard;
			# no cookies/auth are attached (the shared session carries none).
			resp = requests.get(
				current,
				headers={'User-Agent': _UA, 'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'},
				timeout=timeout,
				allow_redirects=False,
				stream=True,
			)
		except Exception as e:  # noqa: BLE001 - network error is data for the model
			debug(f'fetch_url error for {current}: {e}', sub='ai.fetch_url')
			return None, f'failed to fetch {current!r}: {e}'

		if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
			loc = resp.headers.get('Location', '')
			resp.close()
			if not loc:
				return None, f'redirect from {current!r} with no Location'
			current = urljoin(current, loc)
			continue

		content_type = (resp.headers.get('Content-Type') or '').lower()
		if not any(t in content_type for t in _TEXT_CT):
			resp.close()
			return None, f'content-type {content_type or "(unknown)"!r} is not text; not fetching binary content'

		try:
			raw = resp.raw.read(_MAX_BYTES + 1, decode_content=True)
		except Exception as e:  # noqa: BLE001
			resp.close()
			return None, f'failed reading body of {current!r}: {e}'
		finally:
			resp.close()
		body = raw[:_MAX_BYTES].decode(resp.encoding or 'utf-8', 'replace')

		title, text = _extract_text(body, content_type)
		truncated = len(text) > max_chars
		if truncated:
			text = text[:max_chars] + '\n... [truncated]'
		return {
			'url': current,
			'status': resp.status_code,
			'content_type': content_type,
			'title': title,
			'text': text,
			'truncated': truncated,
		}, None

	return None, f'too many redirects (>{_MAX_REDIRECTS})'
