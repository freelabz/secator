from secator.config import CONFIG
from secator.decorators import task

# fmt: off
from secator.definitions import (
	DATA, DELAY, DEPTH, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT, HEADER, MATCH_CODES,
	MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, REPLAY_PROXY, RETRIES, THREADS,
	TIMEOUT, URL, USER_AGENT, WORDLIST
)
# fmt: on
from secator.output_types import Url
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpFuzzer
from secator.utils import process_wordlist


@task()
class kiterunner(HttpFuzzer):
	"""Contextual content discovery tool for API endpoints.

	Uses Assetnote's compiled route wordlists (`-A`) which embed the expected HTTP method, content-type and body for
	each route, making it far more accurate than a plain path fuzzer. A custom plaintext or `.kite` wordlist can be
	passed with `-w`, in which case it overrides the Assetnote wordlist.
	"""
	cmd = 'kr scan'
	input_types = [URL]
	output_types = [Url]
	tags = ['url', 'fuzz', 'api']
	input_flag = None
	input_chunk_size = 1
	file_flag = None
	json_flag = '-o json -q'
	opt_prefix = '--'  # kiterunner uses cobra: long flags require a double dash
	item_loaders = [JSONSerializer()]
	# Override the inherited WORDLIST so it has no default: -w is only passed when the user explicitly provides a
	# custom wordlist, otherwise the Assetnote wordlist (-A) is used.
	meta_opts = {
		**HttpFuzzer.meta_opts,
		WORDLIST: {'type': str, 'short': 'w', 'process': process_wordlist, 'help': 'Custom plaintext/.kite wordlist (overrides --assetnote-wordlist)'},  # noqa: E501
	}
	opts = {
		'assetnote_wordlist': {'type': str, 'short': 'A', 'default': 'apiroutes-210228:20000', 'help': 'Assetnote route wordlist(s), e.g "apiroutes-210228:20000"'},  # noqa: E501
		'max_connection_per_host': {'type': int, 'short': 'x', 'default': 3, 'help': 'Max connections to a single host'},
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: 'delay',
		METHOD: 'force-method',
		THREADS: 'max-parallel-hosts',
		TIMEOUT: 'timeout',
		USER_AGENT: 'user-agent',
		WORDLIST: 'kitebuilder-list',
		MATCH_CODES: 'success-status-codes',
		FILTER_CODES: 'fail-status-codes',
		# kiterunner opts
		'assetnote_wordlist': 'assetnote-wordlist',
		'max_connection_per_host': 'max-connection-per-host',
		# unsupported
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		REPLAY_PROXY: OPT_NOT_SUPPORTED,
		DATA: OPT_NOT_SUPPORTED,
		DEPTH: OPT_NOT_SUPPORTED,
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
	}
	encoding = 'ansi'
	install_version = '1.0.2'
	install_github_bin = False
	install_cmd = (
		'wget -qO /tmp/kiterunner.tar.gz https://github.com/assetnote/kiterunner/releases/download/v[install_version]/kiterunner_[install_version]_linux_amd64.tar.gz '  # noqa: E501
		f'&& tar -xzf /tmp/kiterunner.tar.gz -C {CONFIG.dirs.bin} kr '
		f'&& chmod +x {CONFIG.dirs.bin}/kr && rm -f /tmp/kiterunner.tar.gz'
	)
	github_handle = 'assetnote/kiterunner'
	version_flag = OPT_NOT_SUPPORTED
	proxychains = False
	proxy_socks5 = False
	proxy_http = False

	@staticmethod
	def on_cmd_opts(self, opts):
		# When a custom wordlist (-w) is provided, drop the Assetnote wordlist (-A) to avoid conflicting sources.
		if opts.get(WORDLIST, {}).get('value'):
			opts.pop('assetnote_wordlist', None)
		return opts

	@staticmethod
	def validate_item(self, item):
		if isinstance(item, dict):
			return 'method' in item and bool(item.get('responses'))
		return False

	@staticmethod
	def on_json_loaded(self, item):
		responses = item.get('responses') or []
		if not responses:
			return
		response = responses[0]
		url = response.get('uri') or f"{item.get('target', '')}{item.get('path', '')}"
		yield Url(
			url=url,
			status_code=response.get('sc', 0),
			content_length=response.get('len', 0),
			method=item.get('method', 'GET'),
			request_headers=self.get_opt_value('header', preprocess=True),
			confidence='low',
			tags=['fuzz', 'api'],
		)
