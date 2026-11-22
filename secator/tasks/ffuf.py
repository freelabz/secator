import random
import re
import string
import warnings
from collections import Counter

import requests
from urllib3.exceptions import InsecureRequestWarning

from secator.decorators import task

# fmt: off
from secator.definitions import (
	AUTO_CALIBRATION, DATA, DELAY, DEPTH, EXTRA_DATA, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
	FOLLOW_REDIRECT, HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, PERCENT,
	PROXY, RATE_LIMIT, REPLAY_PROXY, RETRIES, STRING, THREADS, TIMEOUT, URL, USER_AGENT, WORDLIST
)
# fmt: on
from secator.output_types import Info, Progress, Subdomain, Url, Warning
from secator.serializers import JSONSerializer, RegexSerializer
from secator.tasks._categories import HttpFuzzer
from secator.utils import extract_domain_info

# Host-header (virtual host) fuzzing: number of random, valid DNS labels probed before the
# run to fingerprint how the server answers a name that does not exist. A catch-all or
# wildcard virtual host answers every name, sometimes with one of several pages (a pool
# of backends, A/B or cache variants), which ffuf's own calibration does not capture.
VHOST_BASELINE_PROBES = 8
VHOST_BASELINE_TIMEOUT = 10
# Warn when at least this many host-header hits came out and this share of them carry
# the same response fingerprint: the server most likely answers any virtual host.
VHOST_DOMINANT_MIN_HITS = 10
VHOST_DOMINANT_RATIO = 0.8

# The bare auto-calibration flag (not -acc / -ach / -acs).
AC_FLAG_REGEX = re.compile(r'\s-ac(?=\s|$)')

FFUF_PROGRESS_REGEX = r':: Progress: \[(?P<count>\d+)/(?P<total>\d+)\] :: Job \[\d/\d\] :: (?P<rps>\d+) req/sec :: Duration: \[(?P<duration>[\d:]+)\] :: Errors: (?P<errors>\d+) ::'  # noqa: E501


@task()
class ffuf(HttpFuzzer):
	"""Fast web fuzzer written in Go."""

	cmd = 'ffuf -noninteractive'
	input_types = [URL, STRING]
	output_types = [Url, Subdomain, Progress]
	tags = ['url', 'fuzz']
	input_flag = '-u'
	input_chunk_size = 1
	file_flag = None
	json_flag = '-json'
	version_flag = '-V'
	item_loaders = [
		JSONSerializer(strict=True),
		RegexSerializer(FFUF_PROGRESS_REGEX, fields=['count', 'total', 'rps', 'duration', 'errors']),
	]
	opts = {
		AUTO_CALIBRATION: {'is_flag': True, 'default': True, 'short': 'ac', 'help': 'Auto-calibration'},
		'recursion': {'is_flag': True, 'default': False, 'short': 'recursion', 'help': 'Recursion'},
		'stop_on_error': {'is_flag': True, 'default': False, 'short': 'soe', 'help': 'Stop on error'},
		'subs': {'is_flag': True, 'default': False, 'internal': True, 'help': 'Find subdomains (host header fuzzing)'},
	}
	opt_key_map = {
		HEADER: 'H',
		DATA: 'd',
		DELAY: 'p',
		DEPTH: 'recursion-depth',
		FILTER_CODES: 'fc',
		FILTER_REGEX: 'fr',
		FILTER_SIZE: 'fs',
		FILTER_WORDS: 'fw',
		FOLLOW_REDIRECT: 'r',
		MATCH_CODES: 'mc',
		MATCH_REGEX: 'mr',
		MATCH_SIZE: 'ms',
		MATCH_WORDS: 'mw',
		METHOD: 'X',
		PROXY: 'x',
		RATE_LIMIT: 'rate',
		REPLAY_PROXY: 'replay-proxy',
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 't',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
		# ffuf opts
		WORDLIST: 'w',
		AUTO_CALIBRATION: 'ac',
		'stop_on_error': 'sa',
	}
	output_map = {
		Progress: {
			PERCENT: lambda x: int(int(x['count']) * 100 / int(x['total'])),
			EXTRA_DATA: lambda x: x,
		},
	}
	encoding = 'ansi'
	has_fuzz_keyword = False
	install_version = 'v2.1.0'
	install_cmd = 'go install -v github.com/ffuf/ffuf/v2@[install_version]'
	github_handle = 'ffuf/ffuf'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True

	@staticmethod
	def before_init(self):
		# Call parent's before_init to process raw HTTP request
		HttpFuzzer.before_init(self)

		# Add /FUZZ to URL if needed
		recursion = self.get_opt_value('recursion')
		data = self.get_opt_value('data') or ''
		headers = self.get_opt_value('header') or ''
		fuzz_in_headers = 'FUZZ' in headers
		fuzz_in_data = 'FUZZ' in data
		if not self.inputs:
			return
		fuzz_in_url = 'FUZZ' in self.inputs[0]
		self.has_fuzz_keyword = fuzz_in_headers or fuzz_in_data or fuzz_in_url
		subs = self.get_opt_value('subs')
		needs_fuzz_in_url = not fuzz_in_url and (recursion or (not fuzz_in_headers and not fuzz_in_data and not subs))
		if needs_fuzz_in_url:
			self._print(Info(message='Adding /FUZZ to URL as it is missing (not in header, not in data, or recursion is enabled)'), rich=True)  # noqa: E501
			self.inputs[0] = self.inputs[0].rstrip('/') + '/FUZZ'

	@staticmethod
	def on_cmd_opts(self, opts):
		# Fuzz host header
		self.vhost_base = None
		if self.get_opt_value('subs') and len(self.inputs) > 0 and not self.has_fuzz_keyword:
			host = self.inputs[0].split('://')[1].split('/')[0]
			opts['header']['value']['Host'] = f'FUZZ.{host}'
			self.vhost_base = host
			if self.get_opt_value('wordlist') == 'http':
				self.add_result(Info(message='Changing wordlist to combined_subdomains as the default http wordlist is not suitable for fuzzing host header'))  # noqa: E501
				opts['wordlist']['value'] = 'combined_subdomains'
		self.headers = opts['header']['value'].copy()
		return opts

	@staticmethod
	def on_start(self):
		self.vhost_baseline = set()
		self.vhost_fingerprints = Counter()
		self.vhost_dropped = 0
		# Only the process that runs ffuf probes (not the parent of chunked runs), and never
		# when the run is already refused (e.g. a requested proxy that did not resolve).
		if not getattr(self, 'vhost_base', None) or self.has_children or self.errors_count:
			return
		proxies, skip_reason = vhost_probe_proxies(self)
		if skip_reason:
			self.add_result(Warning(message=f'Virtual host baseline skipped ({skip_reason}): catch-all hosts are only filtered by auto-calibration'))  # noqa: E501
			return
		self.vhost_baseline = probe_vhost_baseline(self, self.inputs[0], self.vhost_base, proxies=proxies)
		if not self.vhost_baseline:
			self.add_result(Warning(message='Virtual host baseline got no answer: catch-all hosts are only filtered by auto-calibration'))  # noqa: E501
			return
		fps = ', '.join(sorted(f'status {fp[1]} size {fp[2]}' for fp in self.vhost_baseline if fp[0] == 'size'))
		self._print(Info(message=f'Virtual host baseline (random names): {fps}. Matching hits are dropped.'), rich=True)
		# ffuf calibrates on two answers per strategy, so a server answering one of several
		# pages defeats it, and its fallback filters (e.g. on line count) then hide real
		# virtual hosts too. The baseline replaces it in this mode.
		if AC_FLAG_REGEX.search(self.cmd):
			self.cmd = AC_FLAG_REGEX.sub('', self.cmd)
			if self.cmd_redacted:
				self.cmd_redacted = AC_FLAG_REGEX.sub('', self.cmd_redacted)
			self._print(Info(message='Auto-calibration replaced by the virtual host baseline'), rich=True)

	@staticmethod
	def on_json_loaded(self, item):
		if 'host' in item:
			self.current_host = item['host']
		headers = self.headers.copy()
		host_header_mode = 'FUZZ' in headers.get('Host', '')
		if host_header_mode:
			headers['Host'] = self.current_host
		content_length = item.get('length', 0)
		status_code = item.get('status', 0)
		if host_header_mode:
			# Same answer as for a random, non-existent name: the server answers any
			# virtual host, so this name proves nothing.
			if matches_vhost_baseline(getattr(self, 'vhost_baseline', ()), status_code, content_length, item.get('words'), item.get('lines')):  # noqa: E501
				self.vhost_dropped += 1
				return
			fingerprints = getattr(self, 'vhost_fingerprints', None)
			if fingerprints is not None:
				fingerprints[(status_code, content_length, item.get('words'), item.get('lines'))] += 1
		has_status_code_3xx = str(status_code).startswith('3')
		# ffuf always sets `redirectlocation` (empty when there is none).
		is_redirect = bool(item.get('redirectlocation')) or has_status_code_3xx
		auto_calibration = self.get_opt_value('auto_calibration')
		yield Url(
			url=item['url'],
			host=item['host'],
			# A host-header hit is a response from the base URL with another Host: it does
			# not show that the name resolves or serves anything of its own.
			verified=bool(auto_calibration) and not host_header_mode,
			status_code=status_code,
			content_length=content_length,
			content_type=item['content-type'],
			is_redirect=is_redirect,
			time=item['duration'] * 10**-9,
			method=self.get_opt_value(METHOD) or 'GET',
			request_headers=headers,
			# 'high' marks a Url verified (see Url.__post_init__): not for host-header hits.
			confidence='high' if auto_calibration and not host_header_mode else 'medium',
			tags=['fuzz'],
		)
		has_body = content_length != 0
		if self.get_opt_value('subs'):
			sources = ['http_host_header'] if not self.has_fuzz_keyword else ['http_url']
			yield Subdomain(
				host=item['host'],
				verified=False,
				domain=extract_domain_info(item['host'], domain_only=True),
				extra_data={
					'http_body': has_body,
					'http_status_code': status_code,
					'http_redirect': is_redirect,
				},
				sources=sources,
			)

	@staticmethod
	def on_cmd_done(self):
		if getattr(self, 'vhost_dropped', 0):
			yield Info(message=f'Dropped {self.vhost_dropped} host-header hits matching the random-name baseline')
		warning = dominant_fingerprint_warning(getattr(self, 'vhost_fingerprints', None) or Counter())
		if warning:
			yield Warning(message=warning)

	@staticmethod
	def on_line(self, line):
		if line.startswith('[ERR]'):
			message = line.split('[ERR]')[1].strip()
			yield Warning(message=message)
		# stderr progress and stdout results share the output stream, so a result often
		# arrives glued after a progress update on the same line, and the strict JSON
		# loader would drop it. Split them.
		start = line.find('{"input"')
		if start > 0:
			yield line[:start]
			line = line[start:]
		yield line


def random_dns_label(length=12):
	"""A random, valid DNS label (lowercase letters and digits, starting with a letter)."""
	return random.choice(string.ascii_lowercase) + ''.join(
		random.choices(string.ascii_lowercase + string.digits, k=length - 1))


def response_shape(status, body):
	"""``(status, size, words, lines)`` of an answer, counted the way ffuf counts them (bytes;
	words split on spaces; lines split on newlines)."""
	body = body.encode() if isinstance(body, str) else (body or b'')
	return status, len(body), len(body.split(b' ')), len(body.split(b'\n'))


def baseline_fingerprints(shapes):
	"""Fingerprints of the probe answers: ``('size', status, size)`` for each, plus
	``('shape', status, words, lines)`` only for a shape the probes answered with several
	sizes, i.e. a catch-all page echoing the requested name (probe labels vary in length).
	A shape alone (e.g. one-line minified pages) is too loose to drop hits on otherwise."""
	fingerprints = {('size', status, size) for status, size, _, _ in shapes}
	sizes_by_shape = {}
	for status, size, words, lines in shapes:
		sizes_by_shape.setdefault((status, words, lines), set()).add(size)
	for (status, words, lines), sizes in sizes_by_shape.items():
		if len(sizes) > 1:
			fingerprints.add(('shape', status, words, lines))
	return fingerprints


def matches_vhost_baseline(baseline, status, size, words, lines):
	"""True if a hit answers like one of the random, non-existent names did."""
	return ('size', status, size) in baseline or ('shape', status, words, lines) in baseline


def vhost_probe_proxies(self):
	"""``(proxies, skip_reason)`` for the baseline probes: they must take the same route as
	ffuf, so a requested proxy that did not resolve to a URL usable here skips them."""
	requested = getattr(self, 'proxy', None)
	if not requested:
		return None, None
	proxy = self.get_opt_value(PROXY)
	if not proxy or '://' not in str(proxy):
		return None, f'proxy "{requested}" not usable for the probes'
	if str(proxy).startswith('socks'):
		try:
			import socks  # noqa: F401  (PySocks, needed by requests for SOCKS)
		except ImportError:
			return None, 'SOCKS proxy needs the PySocks package'
	return {'http': proxy, 'https': proxy}, None


def probe_vhost_baseline(self, url, base, probes=VHOST_BASELINE_PROBES, proxies=None):
	"""Request ``url`` with ``probes`` random, non-existent ``Host: <label>.<base>`` names and
	return their fingerprints (see baseline_fingerprints). Mirrors ffuf's request: headers (its
	default User-Agent when none is set), method and body, gzip only, timeout and redirects.
	Stops at the first connection failure; returns an empty set when no probe got an answer."""
	headers = {k: v for k, v in (self.headers or {}).items() if k.lower() != 'host'}
	header_names = {k.lower() for k in headers}
	if 'user-agent' not in header_names:
		headers['User-Agent'] = f'Fuzz Faster U Fool {ffuf.install_version}'
	if 'accept-encoding' not in header_names:
		headers['Accept-Encoding'] = 'gzip'  # what Go's client sends
	data = self.get_opt_value(DATA) or None
	method = self.get_opt_value(METHOD) or ('POST' if data else 'GET')
	timeout = float(self.get_opt_value(TIMEOUT) or VHOST_BASELINE_TIMEOUT)
	follow = bool(self.get_opt_value(FOLLOW_REDIRECT))
	url = url.replace('FUZZ', '')
	shapes = []
	# A plain session, no retries: a catch-all answering 5xx is an answer to record.
	with requests.Session() as session, warnings.catch_warnings():
		warnings.simplefilter('ignore', InsecureRequestWarning)
		for _ in range(probes):
			label = random_dns_label(random.randint(8, 16))
			try:
				resp = session.request(
					method, url, headers={**headers, 'Host': f'{label}.{base}'}, data=data,
					allow_redirects=follow, timeout=timeout, proxies=proxies, verify=False)
			except (requests.ConnectionError, requests.Timeout):
				break  # unreachable: do not wait out every probe
			except requests.RequestException:
				continue
			shapes.append(response_shape(resp.status_code, resp.content))
	return baseline_fingerprints(shapes)


def dominant_fingerprint_warning(fingerprints, min_hits=VHOST_DOMINANT_MIN_HITS, ratio=VHOST_DOMINANT_RATIO):
	"""Warning text when most host-header hits share one response fingerprint, else None."""
	total = sum(fingerprints.values())
	if total < min_hits:
		return None
	(status, size, words, lines), count = fingerprints.most_common(1)[0]
	if count < ratio * total:
		return None
	return (
		f'{count} of {total} host-header hits share one response (status {status}, size {size}, '
		f'{words} words, {lines} lines): the server likely answers any virtual host (catch-all), '
		'so these subdomains are probably false positives')
