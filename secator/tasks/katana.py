import os
import shlex

from urllib.parse import urlparse, urlunparse

from secator.decorators import task
from secator.definitions import (DELAY, DEPTH, FILTER_CODES, FILTER_REGEX, FILTER_SIZE, FILTER_WORDS,
								 FOLLOW_REDIRECT, HEADER, MATCH_CODES, MATCH_REGEX, MATCH_SIZE, MATCH_WORDS,
								 METHOD, OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, URL, USER_AGENT)
from secator.config import CONFIG
from secator.output_types import Url, Tag
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpCrawler

EXCLUDED_PARAMS = ['v']


@task()
class katana(HttpCrawler):
	"""Next-generation crawling and spidering framework."""
	cmd = 'katana'
	input_types = [URL]
	output_types = [Url, Tag]
	tags = ['url', 'crawl']
	file_flag = '-list'
	input_flag = '-u'
	json_flag = '-jsonl'
	opts = {
		'headless': {'is_flag': True, 'short': 'hl', 'help': 'Headless mode'},
		'system_chrome': {'is_flag': True, 'short': 'sc', 'help': 'Use local installed chrome browser'},
		'form_extraction': {'is_flag': True, 'short': 'fx', 'help': 'Detect forms'},
		'store_responses': {'is_flag': True, 'short': 'sr', 'default': CONFIG.http.store_responses, 'help': 'Store responses'},  # noqa: E501
		'form_fill': {'is_flag': True, 'short': 'ff', 'help': 'Enable form filling'},
		'js_crawl': {'is_flag': True, 'short': 'jc', 'default': False, 'help': 'Enable endpoint parsing / crawling in javascript file'},  # noqa: E501
		'jsluice': {'is_flag': True, 'short': 'jsl', 'default': False, 'help': 'Enable jsluice parsing in javascript file (memory intensive)'},  # noqa: E501
		'known_files': {'type': str, 'short': 'kf', 'default': 'all', 'help': 'Enable crawling of known files (all, robotstxt, sitemapxml)'},  # noqa: E501
		'omit_raw': {'is_flag': True, 'short': 'or', 'default': True, 'help': 'Omit raw requests/responses from jsonl output'},  # noqa: E501
		'omit_body': {'is_flag': True, 'short': 'ob', 'default': True, 'help': 'Omit response body from jsonl output'},
		'no_sandbox': {'is_flag': True, 'short': 'ns', 'default': False, 'help': 'Disable sandboxing'},
	}
	opt_key_map = {
		HEADER: 'headers',
		DELAY: 'delay',
		DEPTH: 'depth',
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
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retry',
		THREADS: 'concurrency',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
		'store_responses': 'sr',
		'form_fill': 'aff'
	}
	opt_value_map = {
		DELAY: lambda x: int(x) if isinstance(x, float) else x
	}
	item_loaders = [JSONSerializer()]
	install_pre = {'apk': ['libc6-compat']}
	install_version = 'v1.3.0'
	install_cmd = 'go install -v github.com/projectdiscovery/katana/cmd/katana@[install_version]'
	github_handle = 'projectdiscovery/katana'
	proxychains = False
	proxy_socks5 = True
	proxy_http = True
	profile = lambda opts: katana.dynamic_profile(opts)  # noqa: E731

	@staticmethod
	def dynamic_profile(opts):
		headless = katana._get_opt_value(
			opts,
			'headless',
			opts_conf=dict(katana.opts, **katana.meta_opts),
			opt_aliases=opts.get('aliases', [])
		)
		return 'cpu' if headless is True else 'io'

	@staticmethod
	def on_init(self):
		form_fill = self.get_opt_value('form_fill')
		form_extraction = self.get_opt_value('form_extraction')
		store_responses = self.get_opt_value('store_responses')
		if form_fill or form_extraction or store_responses:
			reports_folder_outputs = f'{self.reports_folder}/.outputs'
			self.cmd += f' -srd {shlex.quote(reports_folder_outputs)}'
		self.tags = []
		self.urls = []

	@staticmethod
	def on_json_loaded(self, item):
		# form detection
		response = item.get('response', {})
		forms = response.get('forms', [])
		parsed_url = urlparse(item['request']['endpoint'])
		url_without_params = urlunparse(parsed_url._replace(query=''))
		params = parsed_url.query.split('&')
		if forms:
			for form in forms:
				method = form['method']
				url = Url(
					form['action'],
					host=parsed_url.hostname,
					method=method,
					stored_response_path=response["stored_response_path"],
					request_headers=self.get_opt_value('header', preprocess=True)
				)
				if url not in self.urls:
					self.urls.append(url)
					yield url
				params = form.get('parameters', [])
				yield Tag(
					category='info',
					name='form',
					value=form['action'],
					match=form['action'],
					stored_response_path=response["stored_response_path"],
					extra_data={
						'method': form['method'],
						'enctype': form.get('enctype', ''),
						'parameters': params
					}
				)
				for param in params:
					yield Tag(
						category='info',
						name='form_param',
						match=form['action'],
						value=param,
						extra_data={'form_url': url}
					)
		response = item.get('response')
		if not response:
			return item
		url = Url(
			url=item['request']['endpoint'],
			host=parsed_url.hostname,
			method=item['request']['method'],
			request_headers=self.get_opt_value('header', preprocess=True),
			time=item['timestamp'],
			status_code=item['response'].get('status_code'),
			content_length=item['response'].get('content_length', 0),
			tech=item['response'].get('technologies', []),
			stored_response_path=item['response'].get('stored_response_path', ''),
			response_headers=item['response'].get('headers', {}),
		)
		if url not in self.urls:
			self.urls.append(url)
			yield url
		for param in params:
			if not param:
				continue
			split_param = param.split('=')
			param_name = split_param[0]
			param_value = None
			if len(split_param) > 1:
				param_value = split_param[1]
			if param_name in EXCLUDED_PARAMS:
				continue
			tag = Tag(
				category='info',
				name='url_param',
				value=param_name,
				match=url_without_params,
				extra_data={'value': param_value, 'url': item['request']['endpoint']}
			)
			if tag not in self.tags:
				self.tags.append(tag)
				yield tag

	@staticmethod
	def on_item(self, item):
		if not isinstance(item, (Url, Tag)):
			return item
		store_responses = self.get_opt_value('store_responses')
		if store_responses and os.path.exists(item.stored_response_path):
			with open(item.stored_response_path, 'r', encoding='latin-1') as fin:
				data = fin.read().splitlines(True)
				if not data:
					return item
				first_line = data[0]
			with open(item.stored_response_path, 'w', encoding='latin-1') as fout:
				fout.writelines(data[1:])
				fout.writelines('\n')
				fout.writelines(first_line)
		return item

	@staticmethod
	def on_end(self):
		store_responses = self.get_opt_value('store_responses')
		index_rpath = f'{self.reports_folder}/.outputs/index.txt'
		if store_responses and os.path.exists(index_rpath):
			os.remove(index_rpath)
