import os

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
								 HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
								 PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, URL, USER_AGENT, HOST, IP, HOST_PORT, SLUG, STRING, OPT_PIPE_INPUT)
from secator.config import CONFIG
from secator.output_types import Ip, Subdomain, Tag
from secator.serializers import JSONSerializer
from secator.tasks._categories import Command
from secator.utils import (sanitize_url, extract_domain_info, extract_subdomains_from_fqdn)


@task()
class getasn(Command):
	"""Get ASN information from IP address."""
	cmd = 'getasn'
	input_chunk_size = 1
	input_types = [IP, HOST]
	input_flag = OPT_PIPE_INPUT
	file_flag = None
	output_types = [Tag]
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
	install_version = 'latest'
	install_cmd = 'go install github.com/Vulnpire/getasn@[install_version]'
	# install_github_handle = 'Vulnpire/getasn'
	proxychains = False
	proxy_socks5 = True
	proxy_http = False

	@staticmethod
	def item_loader(self, line):
		tag = Tag(name=line.strip(), match=self.inputs[0], type='asn')
		if tag not in self.self_results:
			yield tag
