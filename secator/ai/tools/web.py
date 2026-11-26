"""AI tools that reach the public web: ``fetch_url`` (read one page) and ``web_search``
(discover pages).

``fetch_url``
-------------
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

``web_search``
--------------
Keyless web search backends for the AI ``web_search`` tool.

The AI agent often needs live external context — a CVE write-up, a PoC repo, a
config-hardening note — that isn't in the workspace. This module gives it that
without any API key or extra dependency:

``duckduckgo_search`` scrapes the keyless DuckDuckGo HTML endpoint (general web).
``sploitus_search`` queries the keyless Sploitus JSON endpoint (exploits / PoCs / tools).
``tavily_search`` is used ONLY when ``addons.ai.web_search.tavily_api_key`` is set
(a synthesized-answer engine); otherwise it is skipped.
``keenable_search`` is opt-in: used ONLY when ``addons.ai.web_search.keenable_api_key`` is
set or ``keenable_keyless`` is true. It then runs before DuckDuckGo for 'answer' (after
Tavily) and 'links', and falls back to DuckDuckGo when it errors or returns nothing.

``web_search`` is the single orchestrator the handler calls: it picks the engine
from ``mode`` and returns a list of plain result dicts. Everything uses
``secator.requests`` (the shared retry session) and fails soft — a search error
comes back as an empty list, never an exception that aborts the AI loop.

When ``addons.ai.web_proxy_url`` is set, every engine goes through that proxy (the same one
``fetch_url`` uses). The DuckDuckGo HTML engine uses stdlib ``urllib``, which only speaks
http(s) proxies: with a socks proxy it is skipped and the Instant-Answer fallback is used.

Design mirrors Pentagi's ``web_search`` (unified query + intent ``mode``, keyless
DuckDuckGo/Sploitus as the always-available engines), trimmed to what secator
needs and to zero new dependencies.
"""
import ipaddress
import re
import socket
import requests as _requests_lib
import html
import urllib.request
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from requests.adapters import HTTPAdapter
from typing import Dict, Generator
from secator.utils import debug
from secator.output_types import Ai, Error, Info
from secator.ai.utils import _decrypt_dict
from secator.ai.actions import ActionContext, _get_result_context
from secator.ai.tools.base import BaseTool
from secator.config import CONFIG
from secator.requests import requests


# ---------- fetch_url ----------

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


# ---------- web_search ----------

# Browser-like UA — the keyless HTML/JSON endpoints reject the default urllib/requests UA.

# A UA alone no longer gets past DuckDuckGo's anomaly gate — a bare request is
# answered with HTTP 202 + a "challenge/anomaly" body (no results). Sending the
# header set a real browser sends (Accept*/Sec-Fetch*/Referer/Origin) clears the
# gate for most queries. (Heavy repeated use from one IP can still be rate-gated;
# see the DDG-Instant-Answer fallback in web_search().)
_DDG_HEADERS = {
	'User-Agent': _UA,
	'Content-Type': 'application/x-www-form-urlencoded',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Language': 'en-US,en;q=0.9',
	'Origin': 'https://html.duckduckgo.com',
	'Referer': 'https://html.duckduckgo.com/',
	'Sec-Fetch-Dest': 'document',
	'Sec-Fetch-Mode': 'navigate',
	'Sec-Fetch-Site': 'same-origin',
}

_DDG_URL = 'https://html.duckduckgo.com/html/'
# Keyless DuckDuckGo Instant Answer API — reliable (not anomaly-gated) but only
# covers well-known entities/concepts (an abstract + related topics), not a general
# web crawl. Used as the keyless fallback when the HTML endpoint returns nothing.
_DDG_IA_URL = 'https://api.duckduckgo.com/'
_SPLOITUS_URL = 'https://sploitus.com/search'
_TAVILY_URL = 'https://api.tavily.com/search'
_KEENABLE_URL = 'https://api.keenable.ai/v1/search'
# Keyless endpoint: no key, but it requires an X-Keenable-Title header naming the client.
_KEENABLE_PUBLIC_URL = 'https://api.keenable.ai/v1/search/public'
_KEENABLE_TITLE = 'secator'
# Keenable snippets can be long page extracts; keep each result small for the model.
_KEENABLE_SNIPPET_CHARS = 600

# Parse the DuckDuckGo HTML result rows: each hit is an <a class="result__a" href=...>title</a>
# optionally followed by an <a class="result__snippet">snippet</a>. We locate each link, then
# look only in the span up to the next link for that hit's snippet, so a result with no snippet
# doesn't steal the next result's snippet (index-based pairing would drift).
_DDG_LINK_RE = re.compile(r'result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_DDG_SNIPPET_RE = re.compile(r'result__snippet"[^>]*>(.*?)</a>', re.S)

VALID_MODES = ('answer', 'links', 'exploit')


def _proxies():
	"""Explicit AI web proxy (``addons.ai.web_proxy_url``) as a requests proxies dict, or None."""
	return ai_web_proxies() or None


def _urlopen(req, timeout):
	"""``urllib`` open honoring ``addons.ai.web_proxy_url`` (http/https proxies only)."""
	proxies = _proxies()
	if not proxies:
		return urllib.request.urlopen(req, timeout=timeout)
	if not urlparse(proxies['https']).scheme.startswith('http'):
		raise ValueError('socks web_proxy_url is not supported by the urllib engine')
	opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
	return opener.open(req, timeout=timeout)


def _clamp(n, lo, hi, default):
	try:
		n = int(n)
	except (TypeError, ValueError):
		return default
	return max(lo, min(hi, n))


def _strip_tags(s):
	"""Turn an HTML fragment into plain text (unescape entities, drop tags, collapse space)."""
	return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', html.unescape(s or ''))).strip()


def _unwrap_ddg_url(href):
	"""DuckDuckGo sometimes wraps a hit as ``//duckduckgo.com/l/?uddg=<encoded>`` — return the
	real target. An already-direct URL is returned unchanged."""
	if href.startswith('//'):
		href = 'https:' + href
	try:
		parsed = urlparse(href)
	except ValueError:
		return href
	host = parsed.netloc.lower().split(':')[0]
	if (host == 'duckduckgo.com' or host.endswith('.duckduckgo.com')) and parsed.path.startswith('/l/'):
		# parse_qs already percent-decodes `uddg`; decoding again would corrupt any
		# encoded delimiter (e.g. %26 -> &) and point the link at a different query.
		target = parse_qs(parsed.query).get('uddg', [None])[0]
		if target:
			return target
	return href


def duckduckgo_search(query, max_results=5):
	"""Keyless general web search via the DuckDuckGo HTML endpoint.

	Uses stdlib ``urllib`` rather than the shared ``secator.requests`` session ON PURPOSE:
	DuckDuckGo's anomaly gate fingerprints the ``requests``/urllib3 client (TLS + header
	signature) and answers it with HTTP 202 + a challenge body (0 results) EVEN with a full
	browser header set — verified from a datacenter egress: ``requests`` → 202 every time,
	``urllib`` with the same headers → 200 with results. urllib isn't a perfect disguise
	(a busy egress IP still gets rate-gated on some queries, hence the Instant-Answer
	fallback in web_search()), but it's the difference between "never works" and "usually
	works" without a paid key. (For reliable coverage, set addons.ai.web_search.tavily_api_key.)

	Returns a list of ``{"_type": "web_result", "title", "url", "snippet"}`` dicts
	(possibly empty). Raises nothing — network/parse faults return ``[]``.
	"""
	max_results = _clamp(max_results, 1, 25, 5)
	try:
		data = urlencode({'q': query, 'kl': 'us-en'}).encode()
		req = urllib.request.Request(_DDG_URL, data=data, headers=_DDG_HEADERS)
		with _urlopen(req, timeout=_TIMEOUT) as resp:
			status = getattr(resp, 'status', None) or resp.getcode()
			body = resp.read().decode('utf-8', 'ignore')
	except Exception as e:  # noqa: BLE001 - fail soft: an engine error is data, not a crash
		debug(f'duckduckgo search failed: {e}', sub='ai.web_search')
		return []
	# The anomaly gate answers with HTTP 202 (a 2xx, so no exception) and a challenge body
	# carrying no results. Detect it explicitly and fail soft so the caller falls back to
	# the Instant Answer API instead of silently returning "0 results".
	if status == 202 or 'result__a' not in body:
		debug(f'duckduckgo anomaly/empty response (status={status}) for {query!r}',
		      sub='ai.web_search')
		return []
	results = []
	links = list(_DDG_LINK_RE.finditer(body))
	for idx, m in enumerate(links):
		href, title = m.group(1), m.group(2)
		url = _unwrap_ddg_url(html.unescape(href))
		if not url.startswith('http'):
			continue
		# Find this hit's snippet only within the span up to the next result link, so a
		# missing snippet for one result doesn't shift a later snippet onto this URL.
		span_end = links[idx + 1].start() if idx + 1 < len(links) else len(body)
		sm = _DDG_SNIPPET_RE.search(body, m.end(), span_end)
		results.append({
			'_type': 'web_result',
			'title': _strip_tags(title),
			'url': url,
			'snippet': _strip_tags(sm.group(1)) if sm else '',
		})
		if len(results) >= max_results:
			break
	return results


def ddg_instant_answer(query, max_results=5):
	"""Keyless fallback via the DuckDuckGo Instant Answer API (``api.duckduckgo.com``).

	Unlike the HTML endpoint this JSON API is not anomaly-gated, so it stays usable from a
	server IP — but it only knows well-known entities/concepts (a Wikipedia-style abstract
	plus related topics), not a general web crawl. Returns ``web_answer`` (the abstract) +
	``web_result`` (related topics) dicts; empty when the query has no instant answer.
	"""
	max_results = _clamp(max_results, 1, 25, 5)
	try:
		resp = requests.get(
			_DDG_IA_URL,
			params={'q': query, 'format': 'json', 'no_html': '1', 'no_redirect': '1'},
			headers={'User-Agent': _UA, 'Accept': 'application/json'},
			timeout=_TIMEOUT,
			proxies=_proxies(),
		)
		resp.raise_for_status()
		data = resp.json()
	except Exception as e:  # noqa: BLE001 - fail soft
		debug(f'duckduckgo instant-answer failed: {e}', sub='ai.web_search')
		return []
	results = []
	abstract = (data.get('AbstractText') or '').strip()
	if abstract:
		results.append({
			'_type': 'web_answer',
			'title': (data.get('Heading') or query).strip(),
			'url': data.get('AbstractURL') or '',
			'snippet': abstract,
		})

	# RelatedTopics is a mix of flat {Text, FirstURL} entries and {Name, Topics:[...]} groups;
	# walk one level into groups so we surface the individual topic links either way.
	def _flatten(topics):
		for t in topics:
			if isinstance(t, dict) and t.get('Topics'):
				yield from _flatten(t['Topics'])
			elif isinstance(t, dict) and t.get('FirstURL'):
				yield t
	for t in _flatten(data.get('RelatedTopics') or []):
		if len(results) >= max_results:
			break
		results.append({
			'_type': 'web_result',
			'title': (t.get('Text') or '').strip()[:120],
			'url': t.get('FirstURL') or '',
			'snippet': (t.get('Text') or '').strip(),
		})
	return results


def sploitus_search(query, max_results=10, sort='default', exploit_type='exploits'):
	"""Keyless exploit / PoC / offensive-tool search via the Sploitus JSON endpoint.

	``exploit_type``: ``exploits`` (default, exploit code & PoCs) or ``tools``.
	``sort``: ``default`` (relevance), ``date`` (newest), ``score`` (highest CVSS).
	Returns ``{"_type": "exploit_result", "title", "url", "score", "type", "published"}`` dicts.
	"""
	max_results = _clamp(max_results, 1, 25, 10)
	etype = 'tools' if str(exploit_type).lower() == 'tools' else 'exploits'
	sort = sort if sort in ('default', 'date', 'score') else 'default'
	try:
		resp = requests.post(
			_SPLOITUS_URL,
			json={'type': etype, 'sort': sort, 'query': query, 'title': False, 'offset': 0},
			headers={'User-Agent': _UA, 'Accept': 'application/json'},
			timeout=_TIMEOUT,
			proxies=_proxies(),
		)
		resp.raise_for_status()
		data = resp.json()
	except Exception as e:  # noqa: BLE001 - fail soft
		debug(f'sploitus search failed: {e}', sub='ai.web_search')
		return []
	results = []
	for hit in (data.get('exploits') or [])[:max_results]:
		results.append({
			'_type': 'exploit_result',
			'title': (hit.get('title') or '').strip(),
			'url': hit.get('href') or '',
			'score': hit.get('score'),
			'type': (hit.get('type') or '').strip(),
			'published': (hit.get('published') or '').strip(),
		})
	return results


def tavily_search(query, max_results=5, api_key=''):
	"""Synthesized-answer web search via Tavily. Used only when an API key is configured;
	returns ``[]`` (so the caller falls back to DuckDuckGo) when no key is set or on error."""
	if not api_key:
		return []
	max_results = _clamp(max_results, 1, 20, 5)
	try:
		resp = requests.post(
			_TAVILY_URL,
			json={
				'query': query,
				'max_results': max_results,
				'include_answer': True,
				'search_depth': 'basic',
			},
			# Tavily documents Bearer auth for /search: the key goes in the Authorization
			# header, not the JSON body.
			headers={'User-Agent': _UA, 'Authorization': f'Bearer {api_key}'},
			timeout=_TIMEOUT,
			proxies=_proxies(),
		)
		resp.raise_for_status()
		data = resp.json()
	except Exception as e:  # noqa: BLE001 - fail soft: fall back to keyless engine
		debug(f'tavily search failed: {e}', sub='ai.web_search')
		return []
	results = []
	answer = (data.get('answer') or '').strip()
	if answer:
		results.append({'_type': 'web_answer', 'title': 'Synthesized answer', 'url': '', 'snippet': answer})
	for hit in (data.get('results') or [])[:max_results]:
		results.append({
			'_type': 'web_result',
			'title': (hit.get('title') or '').strip(),
			'url': hit.get('url') or '',
			'snippet': (hit.get('content') or '').strip(),
		})
	return results


def keenable_search(query, max_results=5, api_key='', keyless=False):
	"""Web search via Keenable. Opt-in: returns ``[]`` (so the caller falls back to DuckDuckGo)
	unless an API key is set or keyless use is enabled, and on any error."""
	if not api_key and not keyless:
		return []
	max_results = _clamp(max_results, 1, 20, 5)
	headers = {'User-Agent': _UA, 'Content-Type': 'application/json', 'X-Keenable-Title': _KEENABLE_TITLE}
	if api_key:
		headers['X-API-Key'] = api_key
	try:
		resp = requests.post(
			_KEENABLE_URL if api_key else _KEENABLE_PUBLIC_URL,
			json={'query': query, 'max_results': max_results},
			headers=headers,
			timeout=_TIMEOUT,
			proxies=_proxies(),
		)
		resp.raise_for_status()
		data = resp.json()
	except Exception as e:  # noqa: BLE001 - fail soft: fall back to keyless engine
		debug(f'keenable search failed: {e}', sub='ai.web_search')
		return []
	results = []
	for hit in (data.get('results') or [])[:max_results]:
		url = hit.get('url') or ''
		if not url:
			continue
		snippet = ' '.join((hit.get('description') or hit.get('snippet') or '').split())
		results.append({
			'_type': 'web_result',
			'title': (hit.get('title') or '').strip(),
			'url': url,
			'snippet': snippet[:_KEENABLE_SNIPPET_CHARS],
		})
	return results


def web_search(query, mode='answer', max_results=5, exploit_type='exploits', sort='default'):
	"""Run a web search and return ``(results, engine)``.

	mode 'exploit' -> Sploitus (exploit code / PoCs / offensive tools).
	mode 'answer'  -> Tavily when a key is configured (synthesized answer), else DuckDuckGo.
	mode 'links'   -> DuckDuckGo (raw result links + snippets).
	When Keenable is enabled (key or keenable_keyless), it runs before DuckDuckGo in both.

	Never raises: an engine fault yields an empty list. The caller turns ``[]`` into a
	clear "no results" message for the model.
	"""
	mode = mode if mode in VALID_MODES else 'answer'
	if mode == 'exploit':
		return sploitus_search(query, max_results=max_results, sort=sort, exploit_type=exploit_type), 'sploitus'
	ws_cfg = getattr(CONFIG.addons.ai, 'web_search', None)
	tavily_key = getattr(ws_cfg, 'tavily_api_key', '') if ws_cfg is not None else ''
	if mode == 'answer' and tavily_key:
		results = tavily_search(query, max_results=max_results, api_key=tavily_key)
		if results:
			return results, 'tavily'
		# Tavily configured but errored/empty -> fall back to the keyless engine.
	keenable_key = getattr(ws_cfg, 'keenable_api_key', '') if ws_cfg is not None else ''
	keenable_keyless = bool(getattr(ws_cfg, 'keenable_keyless', False)) if ws_cfg is not None else False
	if keenable_key or keenable_keyless:
		results = keenable_search(query, max_results=max_results, api_key=keenable_key, keyless=keenable_keyless)
		if results:
			return results, 'keenable'
		# Keenable enabled but errored/empty -> fall back to DuckDuckGo.
	# Keyless web: the DuckDuckGo HTML endpoint first, then the Instant Answer API when the
	# HTML scrape comes back empty (anomaly-gated or no hits). IA is entity/concept-only, so
	# it's a fallback, not the primary — but it keeps answer/links useful without an API key.
	results = duckduckgo_search(query, max_results=max_results)
	if results:
		return results, 'duckduckgo'
	ia = ddg_instant_answer(query, max_results=max_results)
	if ia:
		return ia, 'duckduckgo_ia'
	return [], 'duckduckgo'


class WebSearch(BaseTool):
	name = "web_search"
	action = "web_search"
	auto_allow = True  # read-only external lookup; no workspace mutation, no target scope
	schema = {
		"type": "function",
		"function": {
			"name": "web_search",
			"description": (
				"Search the public web for live external context — CVE write-ups, PoC/exploit repos, "
				"tool docs, hardening notes. Use this for information NOT in the workspace; use "
				"query_workspace for stored findings. Targets/scope are NOT checked (this reads public "
				"sources, it does not touch the engagement targets)."
			),
			"parameters": {
				"type": "object",
				"properties": {
					"query": {
						"type": "string",
						"description": "The search query. Keep it short and keyword-focused; write it in English (engines index English best)."  # noqa: E501
					},
					"mode": {
						"type": "string",
						"enum": ["answer", "links", "exploit"],
						"description": (
							"What you need back (default 'answer'). 'answer' — a synthesized answer over live "
							"sources when configured, else result links. 'links' — a list of source links with "
							"snippets. 'exploit' — exploit code, PoCs and offensive tools (searches Sploitus)."
						)
					},
					"max_results": {
						"type": "integer",
						"description": "Maximum number of results (1-25; default 5).",
						"default": 5
					},
					"exploit_type": {
						"type": "string",
						"enum": ["exploits", "tools"],
						"description": "exploit mode only: 'exploits' (default) for exploit code/PoCs, 'tools' for offensive-security tools."  # noqa: E501
					},
					"sort": {
						"type": "string",
						"enum": ["default", "date", "score"],
						"description": "exploit mode only: order by relevance (default), date (newest), or score (highest CVSS)."  # noqa: E501
					}
				},
				"required": ["query"]
			}
		}
	}

	def run(self, action: Dict, ctx: ActionContext) -> Generator:
		"""Search the public web for external context (CVE write-ups, PoCs, tool docs).

		Read-only and target-agnostic: it hits public search engines, not the engagement
		targets, so it is NOT gated by target/scope guardrails (see guardrails auto-allow).
		Results are surfaced to the model only (marked ``ai_query_result``) — they are not
		persisted as workspace findings. Fails soft: an engine error yields a clean note,
		never an exception that aborts the AI loop.
		"""
		context = _get_result_context(action, ctx)

		query = action.get("query", "")
		if ctx.encryptor and isinstance(query, str):
			query = _decrypt_dict({"query": query}, ctx.encryptor).get("query", query)
		query = str(query or "").strip()
		if not query:
			yield Error(message="web_search requires a non-empty `query`.", _context=context)
			return

		mode = str(action.get("mode") or "answer").lower()
		if mode not in VALID_MODES:
			mode = "answer"
		max_results = action.get("max_results", 5)
		exploit_type = str(action.get("exploit_type") or "exploits").lower()
		sort = str(action.get("sort") or "default").lower()

		results, engine = web_search(
			query, mode=mode, max_results=max_results, exploit_type=exploit_type, sort=sort)

		yield Ai(
			content=query,
			ai_type="web_search",
			extra_data={"results": results, "count": len(results), "mode": mode, "engine": engine},
			_context=context,
		)
		if not results:
			# Surface an explicit "no results" to the model (mode/engine included) so it can
			# reword the query or switch mode rather than assume the tool is broken.
			yield Info(
				message=f"web_search ({mode} via {engine}) returned no results for {query!r}.",
				_context=context,
			)
			return
		# Surface each hit to the model as an observation-only result (like query_workspace):
		# marked ai_query_result so the runner neither persists nor re-yields it as a finding.
		for hit in results:
			hit = dict(hit)
			hit["_context"] = {**context, "ai_query_result": True}
			yield hit
