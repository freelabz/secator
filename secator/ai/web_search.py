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
from urllib.parse import unquote, urlparse, parse_qs

from secator.config import CONFIG
from secator.requests import requests
from secator.utils import debug

# Browser-like UA — the keyless HTML/JSON endpoints reject the default urllib/requests UA.
_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
_TIMEOUT = 20

_DDG_URL = 'https://html.duckduckgo.com/html/'
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

	Returns a list of ``{"_type": "web_result", "title", "url", "snippet"}`` dicts
	(possibly empty). Raises nothing — network/parse faults return ``[]``.
	"""
	max_results = _clamp(max_results, 1, 25, 5)
	try:
		resp = requests.post(
			_DDG_URL,
			data={'q': query, 'kl': 'us-en'},
			headers={'User-Agent': _UA, 'Content-Type': 'application/x-www-form-urlencoded'},
			timeout=_TIMEOUT,
		)
		resp.raise_for_status()
		body = resp.text
	except Exception as e:  # noqa: BLE001 - fail soft: an engine error is data, not a crash
		debug(f'duckduckgo search failed: {e}', sub='ai.web_search')
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
	return duckduckgo_search(query, max_results=max_results), 'duckduckgo'
