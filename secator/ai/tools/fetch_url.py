"""AI tool: `fetch_url`.

Fetch a single web page and return its readable text — for the AI ``fetch_url`` tool.

This lets the agent READ a specific public page it already knows about (a HackTricks
technique, a vendor advisory, a Debian security-tracker page, a blog post on a fresh CVE),
as opposed to ``web_search`` which discovers pages.

SECURITY — the agent picks the URL, so before every request (and every redirect hop)
:func:`is_safe_public_url` checks the scheme is ``http`` / ``https`` only (no ``file:``,
``gopher:``, ``ftp:``, ``dict:`` …).

Strict SSRF mode (``addons.ai.fetch_url_ssrf_protection``, off by default for local CLI use;
enable on shared or server-side deployments) additionally:

- requires the host to be a global address: an IP literal is checked directly, a hostname
is resolved locally and every A/AAAA record must be global. This blocks the cloud metadata
endpoints (169.254.169.254, 100.100.100.200), loopback (incl. ``localhost``), RFC 1918 and
other internal addresses;
- connects through :class:`_PeerValidatingHTTPAdapter`, which re-validates the *connected*
peer IP and tears the socket down if it is not public (defeats DNS rebinding).

With strict mode off, fetch_url is open: no host/address filtering at all.

Proxy: ``addons.ai.web_proxy_url`` (http/https/socks) is the ONLY proxy ever used — ambient
``HTTP(S)_PROXY`` env vars are ignored (``trust_env=False``) so the proxy that secator tasks
see never changes how the AI reaches the web, and vice-versa. With a proxy, the connected peer
is the proxy itself, so peer validation does not apply; in strict mode the host must still
resolve locally (see :func:`is_safe_public_url`).

Redirects are followed manually so each hop is re-validated; cookies/auth are never sent;
the response is size-capped and only text-like content types are read. All failures are
soft — a blocked or failed fetch returns an error string, never an exception that aborts
the AI loop.
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse, urljoin

import requests as _requests_lib
from requests.adapters import HTTPAdapter

from secator.utils import debug
from typing import Dict, Generator
from secator.output_types import Ai, Error
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool

_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
_TIMEOUT = 20
_MAX_BYTES = 2_000_000        # cap the raw download
_MAX_CHARS_DEFAULT = 20_000   # cap the extracted text handed to the model
_MAX_REDIRECTS = 5
_TEXT_CT = ('text/', 'application/json', 'application/xml', 'application/xhtml', '+json', '+xml', 'application/rss', 'application/atom')  # noqa: E501

_WS_RE = re.compile(r'[ \t\r\f\v]+')
_MULTINL_RE = re.compile(r'\n{3,}')


_PROXY_SCHEMES = ('http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h')
_NO_DNS_HINT = 'no DNS; configure addons.ai.web_proxy_url if behind a proxy'


def _parse_ip_literal(host):
	"""Return an ``ip_address`` if ``host`` is a (bracketed or plain) IP literal, else None."""
	literal = host[1:-1] if host.startswith('[') and host.endswith(']') else host
	try:
		return ipaddress.ip_address(literal)
	except ValueError:
		return None


def _resolve(host):
	"""Resolve ``host`` locally. Returns the set of address strings, or None if it doesn't resolve."""
	try:
		infos = socket.getaddrinfo(host, None)
	except (socket.gaierror, UnicodeError, OSError):
		return None
	return {info[4][0] for info in infos} or None


def _host_is_public(host):
	"""True iff every address ``host`` resolves to is a global (public) IP.

	A hostname with any private/loopback/link-local/reserved record is rejected (fail-closed):
	that closes SSRF to internal services, the cloud metadata IP (link-local 169.254.0.0/16),
	and DNS-rebinding tricks. A host that can't be resolved is rejected too."""
	return _check_host(host, strict=True) is None


def _check_host(host, strict, proxied=False):
	"""Return None if ``host`` may be fetched, else a reason string for the model."""
	if not host:
		return 'URL has no host'
	if not strict:
		return None
	ip = _parse_ip_literal(host)
	if ip is not None:
		if not _ip_is_public(ip):
			return f'host {host} is a private/non-public address (blocked to prevent SSRF)'
		return None
	addrs = _resolve(host)
	if addrs is None:
		if proxied:
			return (
				f'could not resolve host {host} locally: addons.ai.fetch_url_ssrf_protection requires '
				'local DNS to verify the target, even with addons.ai.web_proxy_url set '
				'(disable strict mode or provide a local resolver)')
		return f'could not resolve host {host} ({_NO_DNS_HINT})'
	for a in addrs:
		try:
			public = _ip_is_public(ipaddress.ip_address(a.split('%')[0]))
		except ValueError:
			public = False
		if not public:
			return f'host {host} resolves to a private/non-public address {a} (blocked to prevent SSRF)'
	return None


def _ip_is_public(ip):
	"""Reject every non-global range: private, loopback, link-local, multicast, reserved,
	unspecified — and IPv4-mapped/6to4/Teredo wrappers around a private v4."""
	if isinstance(ip, ipaddress.IPv6Address):
		if ip.ipv4_mapped is not None:
			return _ip_is_public(ip.ipv4_mapped)
		sixtofour = getattr(ip, 'sixtofour', None)
		if sixtofour is not None:
			return _ip_is_public(sixtofour)
	# Require a globally-routable address, AND explicitly reject the usual non-public
	# ranges. `is_global` alone rejects shared/CGNAT space (100.64.0.0/10, e.g. the
	# Alibaba metadata host 100.100.100.200), link-local IPv6 (fe80::/10), etc. — ranges
	# that are neither is_private nor is_reserved and would otherwise slip through.
	return ip.is_global and not (
		ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
		or ip.is_reserved or ip.is_unspecified
	)


def is_safe_public_url(url, strict=True, proxied=False):
	"""Return (ok, reason). reason explains a rejection (for the model).

	Always: http(s) only. strict=True additionally: an IP-literal host must be public, and a
	hostname must resolve locally, entirely to public addresses (when ``proxied``, an
	unresolvable host gets a strict-mode-specific error)."""
	try:
		p = urlparse(url)
		hostname = p.hostname
	except ValueError:
		return False, 'unparseable URL'
	if p.scheme not in ('http', 'https'):
		return False, f"scheme {p.scheme or '(none)'!r} not allowed (http/https only)"
	reason = _check_host(hostname, strict=strict, proxied=proxied)
	if reason:
		return False, reason
	return True, ''


class _PeerValidatingHTTPAdapter(HTTPAdapter):
	"""HTTPAdapter that re-validates the *connected* peer IP, defeating DNS rebinding.

	The pre-flight :func:`is_safe_public_url` resolves the host and checks the records,
	but ``requests`` resolves the host again when it opens the socket, so a TTL-0 domain
	could answer with a public IP for the check and an internal IP for the connection
	(169.254.169.254, an RFC-1918 host, …). This adapter inspects the actual socket's
	peer address after connect and tears the connection down if it is not public."""

	def send(self, request, *args, **kwargs):
		resp = super().send(request, *args, **kwargs)
		sock = getattr(getattr(resp, 'raw', None), '_connection', None)
		# urllib3 keeps the underlying socket on the connection object (.sock).
		real_sock = getattr(getattr(resp.raw, '_fp', None), 'fp', None)
		peer = None
		for candidate in (getattr(sock, 'sock', None), real_sock):
			getpeername = getattr(candidate, 'getpeername', None) if candidate else None
			if getpeername:
				try:
					peer = getpeername()[0]
					break
				except OSError:
					continue
		if peer is not None:
			try:
				if not _ip_is_public(ipaddress.ip_address(peer.split('%')[0])):
					resp.close()
					raise _requests_lib.RequestException(
						f'connection peer {peer} is not a public address (SSRF/DNS-rebinding blocked)')
			except ValueError:
				resp.close()
				raise _requests_lib.RequestException(f'connection peer {peer!r} is not a valid IP')
		return resp


def _ai_web_settings():
	"""Return (strict, proxy_url) from ``addons.ai`` (fetch_url_ssrf_protection, web_proxy_url)."""
	from secator.config import CONFIG
	ai = getattr(CONFIG.addons, 'ai', None)
	strict = bool(getattr(ai, 'fetch_url_ssrf_protection', False))
	proxy = str(getattr(ai, 'web_proxy_url', '') or '').strip()
	return strict, proxy


def check_proxy_url(proxy_url):
	"""Return None if ``proxy_url`` is usable, else an error string.

	socks proxies need PySocks (``pip install 'requests[socks]'``); prefer ``socks5h://`` so
	the proxy resolves hostnames (``socks5://`` resolves locally, which fails with no DNS)."""
	try:
		scheme = urlparse(proxy_url).scheme.lower()
	except ValueError:
		scheme = ''
	if scheme not in _PROXY_SCHEMES:
		return f"addons.ai.web_proxy_url scheme {scheme or '(none)'!r} not supported (use http, https or socks5h)"
	if scheme.startswith('socks'):
		try:
			import socks  # noqa: F401
		except ImportError:
			return "addons.ai.web_proxy_url is a socks proxy but PySocks is not installed (pip install 'requests[socks]')"
	return None


def ai_web_proxies():
	"""``requests``-style proxies dict for AI outbound web calls (empty when no proxy is set)."""
	_, proxy = _ai_web_settings()
	return {'http': proxy, 'https': proxy} if proxy else {}


def _build_session(strict=True, proxy_url=''):
	"""A throwaway session for fetch_url.

	Ambient proxies are always ignored (``trust_env=False``): ``HTTP(S)_PROXY`` / ``NO_PROXY``
	may be set for secator tasks and must not change how the AI reaches the web. The only
	proxy used is the explicit ``proxy_url`` (``addons.ai.web_proxy_url``).

	Strict mode without a proxy mounts the peer-validating adapter (DNS-rebinding guard).
	With a proxy the connected peer is the proxy (often a private IP), so it is not validated."""
	session = _requests_lib.Session()
	session.trust_env = False
	session.proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else {}
	adapter = _PeerValidatingHTTPAdapter() if (strict and not proxy_url) else HTTPAdapter()
	session.mount('http://', adapter)
	session.mount('https://', adapter)
	return session


def _is_dns_failure(exc):
	"""True if a requests/urllib3 error was caused by local name resolution failing."""
	seen = set()
	stack = [exc]
	while stack:
		e = stack.pop()
		if e is None or id(e) in seen:
			continue
		seen.add(id(e))
		if isinstance(e, socket.gaierror) or type(e).__name__ == 'NameResolutionError':
			return True
		stack.extend([e.__cause__, e.__context__, getattr(e, 'reason', None)])
		stack.extend(a for a in getattr(e, 'args', ()) if isinstance(a, BaseException))
	return False


def _extract_text(body, content_type):
	"""Turn an HTML/text body into readable plain text (+ a title for HTML).

	HTML is parsed with BeautifulSoup's ``html.parser`` (linear time) rather than
	regex: the body is attacker-controlled and up to 2 MB, and a lazy ``.*?`` strip
	regex degrades to O(n²) on pages with many unclosed ``<script>``/``<`` openers,
	which would hang the (CPU-unbounded) AI loop. The parser keeps the behavior
	equivalent on well-formed pages (title + script/style/etc. removal + text)."""
	title = ''
	if 'html' in content_type or ('<html' in body[:2000].lower()):
		from bs4 import BeautifulSoup
		soup = BeautifulSoup(body, 'html.parser')
		if soup.title and soup.title.string:
			title = _WS_RE.sub(' ', soup.title.string).strip()
		for el in soup(['script', 'style', 'noscript', 'template', 'svg']):
			el.decompose()
		body = soup.get_text('\n')
	# Normalize whitespace: collapse runs of spaces/tabs, keep paragraph breaks, trim runs of blank lines.
	lines = [_WS_RE.sub(' ', ln).strip() for ln in body.splitlines()]
	text = '\n'.join(ln for ln in lines if ln != '' or True)  # keep single blanks
	text = _MULTINL_RE.sub('\n\n', text).strip()
	return title, text


def fetch_url(url, max_chars=_MAX_CHARS_DEFAULT, timeout=_TIMEOUT, strict=None, proxy_url=None):
	"""Fetch one public page and return (result, error).

	``strict`` / ``proxy_url`` default to ``addons.ai.fetch_url_ssrf_protection`` /
	``addons.ai.web_proxy_url``.

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

	cfg_strict, cfg_proxy = _ai_web_settings()
	strict = cfg_strict if strict is None else bool(strict)
	proxy_url = cfg_proxy if proxy_url is None else str(proxy_url or '').strip()
	if proxy_url:
		err = check_proxy_url(proxy_url)
		if err:
			return None, err

	session = _build_session(strict=strict, proxy_url=proxy_url)
	for _hop in range(_MAX_REDIRECTS + 1):
		ok, reason = is_safe_public_url(current, strict=strict, proxied=bool(proxy_url))
		if not ok:
			return None, f'refused to fetch {current!r}: {reason}'
		try:
			# allow_redirects=False so we re-validate every hop against the SSRF guard;
			# in strict mode the peer-validating adapter also re-checks the connected IP
			# (DNS rebinding); ambient proxies are ignored, and no cookies/auth are attached.
			resp = session.get(
				current,
				headers={'User-Agent': _UA, 'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'},
				timeout=timeout,
				allow_redirects=False,
				stream=True,
			)
		except Exception as e:  # noqa: BLE001 - network error is data for the model
			debug(f'fetch_url error for {current}: {e}', sub='ai.fetch_url')
			if not proxy_url and _is_dns_failure(e):
				return None, f'failed to fetch {current!r}: could not resolve host {urlparse(current).hostname} ({_NO_DNS_HINT})'
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


class FetchUrl(BaseTool):
	name = "fetch_url"
	action = "fetch_url"
	auto_allow = True  # read-only external lookup; SSRF-guarded in the handler, no target scope
	schema = {
		"type": "function",
		"function": {
			"name": "fetch_url",
			"description": (
				"Fetch a single PUBLIC web page and return its readable text — use it to READ a page you "
				"already know (a HackTricks technique, a vendor advisory, a Debian security-tracker page, a "
				"blog post on a fresh CVE). Only public "
				"http(s) pages are allowed; internal/private hosts are refused."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"url": {"type": "string", "description": "The http(s) URL to fetch."},
					"max_chars": {"type": "integer", "description": "Max characters of extracted text to return (default 20000)."}
				},
				"required": ["url"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Fetch one public page and surface its readable text to the model.

		Target-agnostic (reads public sources, not the engagement targets) so it is not
		scope-gated — but the fetch is SSRF-guarded (public http(s) hosts only; internal /
		metadata / private hosts and non-http schemes are refused) so it can't be used to reach
		our own internal surface. Read-only: the page text is observation-only (marked
		ai_query_result), never persisted as a finding. Fails soft.
		"""
		context = _get_result_context(action, ctx)
		url = action.get("url", "")
		if ctx.encryptor and isinstance(url, str):
			url = _decrypt_dict({"url": url}, ctx.encryptor).get("url", url)
		url = str(url or "").strip()
		if not url:
			yield Error(message="fetch_url requires a `url`.", _context=context)
			return
		max_chars = action.get("max_chars", 20000)

		result, error = fetch_url(url, max_chars=max_chars)
		if error:
			yield Error(message=f"fetch_url: {error}", _context=context)
			return

		yield Ai(
			content=result.get("text", ""),
			ai_type="fetch_url",
			extra_data={
				"url": result.get("url"),
				"status": result.get("status"),
				"title": result.get("title"),
				"content_type": result.get("content_type"),
				"truncated": result.get("truncated"),
				"ai_query_result": True,
			},
			_context=context,
		)
		# Surface the extracted text to the model as an observation-only result.
		yield {
			"_type": "web_page",
			"url": result.get("url"),
			"status": result.get("status"),
			"title": result.get("title"),
			"text": result.get("text"),
			"_context": {**context, "ai_query_result": True},
		}
