from secator.decorators import task
from secator.definitions import (DELAY, OPT_PIPE_INPUT, IP, HOST)
from secator.output_types import Tag
from secator.tasks._categories import Command


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
	install_github_bin = False
	github_handle = 'Vulnpire/getasn'
	proxychains = False
	proxy_socks5 = True
	proxy_http = False

	@staticmethod
	def item_loader(self, line):
		tag = Tag(
			category='info',
			name='asn',
			match=self.inputs[0],
			value=line.strip(),
		)
		if tag not in self.self_results:
			yield tag
