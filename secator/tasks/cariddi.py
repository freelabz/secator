import re
from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
							   FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
							   HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, METHOD, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, URL, USER_AGENT)
from secator.output_types import Tag, Url
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpCrawler

CARIDDI_IGNORE_PATTERNS = re.compile(r"|".join([
	r"<!--\s*Instance.*\s*-->",
	r"<!--\s*(Styles|Scripts|Fonts|Images|Links|Forms|Inputs|Buttons|List|Next|Prev|Navigation dots)\s*-->",
	r"<!--\s*end.*-->",
	r"<!--\s*start.*-->",
	r"<!--\s*begin.*-->",
	r"<!--\s*here goes.*-->",
	r"<!--\s*.*Yoast SEO.*\s*-->",
	r"<!--\s*.*Google Analytics.*\s*-->",
]), re.IGNORECASE)

CARIDDI_IGNORE_LIST = ['BTC address']


@task()
class cariddi(HttpCrawler):
	"""Crawl endpoints, secrets, api keys, extensions, tokens..."""
	cmd = 'cariddi'
	input_types = [URL]
	output_types = [Url, Tag]
	tags = ['url', 'crawl']
	input_flag = OPT_PIPE_INPUT
	file_flag = OPT_PIPE_INPUT
	json_flag = '-json'
	opts = {
		'info': {'is_flag': True, 'short': 'info', 'help': 'Hunt for useful informations in websites.'},
		'secrets': {'is_flag': True, 'short': 'secrets', 'help': 'Hunt for secrets.'},
		'errors': {'is_flag': True, 'short': 'err', 'help': 'Hunt for errors in websites.'},
		'juicy_extensions': {'type': int, 'short': 'jext', 'help': 'Hunt for juicy file extensions. Integer from 1(juicy) to 7(not juicy)'},  # noqa: E501
		'juicy_endpoints': {'is_flag': True, 'short': 'jep', 'help': 'Hunt for juicy endpoints.'}
	}
	opt_value_map = {
		HEADER: lambda headers: headers
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: 'd',
		DEPTH: OPT_NOT_SUPPORTED,
		FILTER_CODES: OPT_NOT_SUPPORTED,
		FILTER_REGEX: OPT_NOT_SUPPORTED,
		FILTER_SIZE: OPT_NOT_SUPPORTED,
		FILTER_WORDS: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		MATCH_CODES: OPT_NOT_SUPPORTED,
		MATCH_REGEX: OPT_NOT_SUPPORTED,
		MATCH_SIZE: OPT_NOT_SUPPORTED,
		MATCH_WORDS: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: 'c',
		TIMEOUT: 't',
		USER_AGENT: 'ua',
		'secrets': 's',
		'errors': 'err',
		'juicy_endpoints': 'e',
		'juicy_extensions': 'ext'
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v1.3.6'
	install_cmd = 'go install -v github.com/edoardottt/cariddi/cmd/cariddi@[install_version]'
	install_github_handle = 'edoardottt/cariddi'
	encoding = 'ansi'
	proxychains = False
	proxy_socks5 = True  # with leaks... https://github.com/edoardottt/cariddi/issues/122
	proxy_http = True  # with leaks... https://github.com/edoardottt/cariddi/issues/122
	profile = 'cpu'

	@staticmethod
	def on_json_loaded(self, item):
		url_item = {k: v for k, v in item.items() if k != 'matches'}
		url_item['request_headers'] = self.get_opt_value(HEADER, preprocess=True)
		yield Url(**url_item)

		# Get matches, params, errors, secrets, infos
		url = url_item[URL]
		matches = item.get('matches', {})
		params = matches.get('parameters', [])
		errors = matches.get('errors', [])
		secrets = matches.get('secrets', [])
		infos = matches.get('infos', [])

		for param in params:
			param_name = param['name']
			for attack in param['attacks']:
				extra_data = {'param': param_name, 'source': 'url'}
				yield Tag(
					name=f'{attack} param',
					match=url,
					extra_data=extra_data
				)

		for error in errors:
			match = error['match']
			error['extra_data'] = {'error': match, 'source': 'body'}
			error['match'] = url
			yield Tag(**error)

		for secret in secrets:
			match = secret['match']
			secret['extra_data'] = {'secret': match, 'source': 'body'}
			secret['match'] = url
			yield Tag(**secret)

		for info in infos:
			if info['name'] in CARIDDI_IGNORE_LIST:
				continue
			match = info['match']
			if CARIDDI_IGNORE_PATTERNS.match(match):
				continue
			info['extra_data'] = {'info': match, 'source': 'body'}
			info['match'] = url
			yield Tag(**info)
