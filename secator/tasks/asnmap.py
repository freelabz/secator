import os

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
								 HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
								 PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, URL, USER_AGENT, HOST, IP, HOST_PORT, SLUG, STRING, OPT_PIPE_INPUT)
from secator.config import CONFIG
from secator.output_types import Ip, Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import Command
from secator.utils import (sanitize_url, extract_domain_info, extract_subdomains_from_fqdn)


@task()
class asnmap(Command):
	"""ASN mapping tool."""
	cmd = 'asnmap'
	input_types = [SLUG, STRING]
	input_flag = OPT_PIPE_INPUT
	output_types = [Ip, Subdomain]
	tags = ['ip', 'probe']
	opts = {}
	opt_key_map = {
		# HEADER: 'header',
		# DELAY: 'delay',
		# DEPTH: OPT_NOT_SUPPORTED,
		# FILTER_CODES: 'filter-code',
		# FILTER_REGEX: 'filter-regex',
		# FILTER_SIZE: 'filter-length',
		# FILTER_WORDS: 'filter-word-count',
		# FOLLOW_REDIRECT: 'follow-redirects',
		# MATCH_CODES: 'match-code',
		# MATCH_REGEX: 'match-regex',
		# MATCH_SIZE: 'match-length',
		# MATCH_WORDS: 'match-word-count',
		# METHOD: 'x',
		# PROXY: 'proxy',
		# RATE_LIMIT: 'rate-limit',
		# RETRIES: 'retries',
		# THREADS: 'threads',
		# TIMEOUT: 'timeout',
		# USER_AGENT: OPT_NOT_SUPPORTED,
		# 'store_responses': 'sr',
	}
	opt_value_map = {
		DELAY: lambda x: str(x) + 's' if x else None,
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v1.1.1'
	install_cmd = 'go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@[install_version]'
	install_github_handle = 'projectdiscovery/asnmap'
	proxychains = False
	proxy_socks5 = True
	proxy_http = False
