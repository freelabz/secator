"""Keyless web search backends for the AI ``web_search`` tool.

The AI agent often needs live external context — a CVE write-up, a PoC repo, a
config-hardening note — that isn't in the workspace. This module gives it that
without any API key or extra dependency:

``duckduckgo_search`` scrapes the keyless DuckDuckGo HTML endpoint (general web).
``sploitus_search`` queries the keyless Sploitus JSON endpoint (exploits / PoCs / tools).
``tavily_search`` is used ONLY when ``addons.ai.web_search.tavily_api_key`` is set
(a synthesized-answer engine); otherwise it is skipped.

``web_search`` is the single orchestrator the handler calls: it picks the engine
from ``mode`` and returns a list of plain result dicts. Everything uses
``secator.requests`` (the shared retry session) and fails soft — a search error
comes back as an empty list, never an exception that aborts the AI loop.

Design mirrors Pentagi's ``web_search`` (unified query + intent ``mode``, keyless
DuckDuckGo/Sploitus as the always-available engines), trimmed to what secator
needs and to zero new dependencies.
"""

import html
import re
import urllib.request
from urllib.parse import unquote, urlparse, parse_qs, urlencode

from secator.config import CONFIG
from secator.requests import requests
from secator.utils import debug

# Browser-like UA — the keyless HTML/JSON endpoints reject the default urllib/requests UA.
_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
_TIMEOUT = 20

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

# Parse the DuckDuckGo HTML result rows: each hit is an <a class="result__a" href=...>title</a>
# optionally followed by an <a class="result__snippet">snippet</a>.
_DDG_LINK_RE = re.compile(r'result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_DDG_SNIPPET_RE = re.compile(r'result__snippet"[^>]*>(.*?)</a>', re.S)

VALID_MODES = ('answer', 'links', 'exploit')


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
		target = parse_qs(parsed.query).get('uddg', [None])[0]
		if target:
			return unquote(target)
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
		with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
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
	snippets = [_strip_tags(s) for s in _DDG_SNIPPET_RE.findall(body)]
	results = []
	for i, (href, title) in enumerate(_DDG_LINK_RE.findall(body)):
		url = _unwrap_ddg_url(html.unescape(href))
		if not url.startswith('http'):
			continue
		results.append({
			'_type': 'web_result',
			'title': _strip_tags(title),
			'url': url,
			'snippet': snippets[i] if i < len(snippets) else '',
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
				'api_key': api_key,
				'query': query,
				'max_results': max_results,
				'include_answer': True,
				'search_depth': 'basic',
			},
			headers={'User-Agent': _UA},
			timeout=_TIMEOUT,
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


def web_search(query, mode='answer', max_results=5, exploit_type='exploits', sort='default'):
	"""Run a web search and return ``(results, engine)``.

	mode 'exploit' -> Sploitus (exploit code / PoCs / offensive tools).
	mode 'answer'  -> Tavily when a key is configured (synthesized answer), else DuckDuckGo.
	mode 'links'   -> DuckDuckGo (raw result links + snippets).

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
