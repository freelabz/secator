import re

from urllib.parse import urlparse, urlunparse

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX,
							   FILTER_SIZE, FILTER_WORDS, FOLLOW_REDIRECT,
							   HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE,
							   MATCH_WORDS, OPT_NOT_SUPPORTED,
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
CARIDDI_RENAME_LIST = {
	'IPv4 address': 'IpV4 address',
	'MySQL error': 'Mysql error',
	'MariaDB error': 'Mariadb error',
	'PostgreSQL error': 'Postgresql error',
	'SQLite error': 'Sqlite error',
}


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
	install_version = 'v1.4.4'
	install_cmd = 'go install -v github.com/edoardottt/cariddi/cmd/cariddi@[install_version]'
	github_handle = 'edoardottt/cariddi'
	encoding = 'ansi'
	proxychains = False
	proxy_socks5 = True  # with leaks... https://github.com/edoardottt/cariddi/issues/122
	proxy_http = True  # with leaks... https://github.com/edoardottt/cariddi/issues/122
	profile = lambda opts: cariddi.dynamic_profile(opts)  # noqa: E731

	@staticmethod
	def dynamic_profile(opts):
		juicy_endpoints = cariddi._get_opt_value(
			opts,
			'juicy_endpoints',
			opts_conf=dict(cariddi.opts, **cariddi.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		juicy_extensions = cariddi._get_opt_value(
			opts,
			'juicy_extensions',
			opts_conf=dict(cariddi.opts, **cariddi.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		info = cariddi._get_opt_value(
			opts,
			'info',
			opts_conf=dict(cariddi.opts, **cariddi.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		secrets = cariddi._get_opt_value(
			opts,
			'secrets',
			opts_conf=dict(cariddi.opts, **cariddi.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		errors = cariddi._get_opt_value(
			opts,
			'errors',
			opts_conf=dict(cariddi.opts, **cariddi.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		hunt = juicy_endpoints or (juicy_extensions is not None) or info or secrets or errors
		return 'cpu' if hunt is True else 'io'

	@staticmethod
	def on_json_loaded(self, item):
		url_item = {k: v for k, v in item.items() if k != 'matches'}
		url_item['request_headers'] = self.get_opt_value(HEADER, preprocess=True)
		yield Url(**url_item)

		# Get matches, params, errors, secrets, infos
		url = url_item[URL]
		parsed_url = urlparse(url)
		url_without_param = urlunparse(parsed_url._replace(query=''))
		matches = item.get('matches', {})
		params = matches.get('parameters', [])
		errors = matches.get('errors', [])
		secrets = matches.get('secrets', [])
		infos = matches.get('infos', [])

		for param in params:
			param_name = param['name']
			for attack in param['attacks']:
				extra_data = {k: v for k, v in param.items() if k not in ['name', 'attacks']}
				extra_data['content'] = attack
				if parsed_url.query:
					query_params = parsed_url.query.split('&')
					for p in query_params:
						if '=' not in p:
							continue
						parts = p.split('=', 1)
						p_name = parts[0]
						p_value = parts[1] if len(parts) > 1 else ''
						if p_name == param_name:
							p_value = p_value
							break
						yield Tag(
							category='info',
							name='url_param',
							value=p_name,
							match=url_without_param,
							extra_data={'value': p_value, 'url': url}
						)

		for error in errors:
			error['category'] = 'error'
			error['name'] = '_'.join(f'{error["name"]}'.lower().split())
			error['value'] = error['match']
			error['extra_data'] = {'url': url}
			error['match'] = url_without_param
			yield Tag(**error)

		for secret in secrets:
			secret['category'] = 'secret'
			secret['name'] = '_'.join(f'{secret["name"]}'.lower().split())
			secret['value'] = secret['match']
			secret['extra_data'] = {'url': url}
			secret['match'] = url_without_param
			yield Tag(**secret)

		for info in infos:
			if info['name'] in CARIDDI_IGNORE_LIST:
				continue
			if info['name'] in CARIDDI_RENAME_LIST:
				info['name'] = CARIDDI_RENAME_LIST[info['name']]
			content = info['match']
			info['category'] = 'info'
			info['name'] = '_'.join(f'{info["name"]}'.lower().split())
			info['match'] = url_without_param
			if CARIDDI_IGNORE_PATTERNS.match(content):
				continue
			info['value'] = content
			info['extra_data'] = {'url': url}
			yield Tag(**info)
