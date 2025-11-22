from secator.decorators import task
from secator.definitions import OPT_NOT_SUPPORTED, OPT_PIPE_INPUT, URL
from secator.output_types import Tag, Url
from secator.serializers import JSONSerializer
from secator.tasks._categories import HttpCrawler


@task()
class jsleak(HttpCrawler):
	"""Find secrets and links in JavaScript files."""
	cmd = 'jsleak'
	input_types = [URL]
	output_types = [Tag, Url]
	tags = ['js', 'secret', 'scan']
	input_flag = OPT_PIPE_INPUT
	file_flag = OPT_PIPE_INPUT
	json_flag = '-j'
	opts = {
		'secrets': {'is_flag': True, 'short': 's', 'default': True, 'help': 'Search for secrets'},
		'links': {'is_flag': True, 'short': 'l', 'default': False, 'help': 'Find links/endpoints'},
		'complete': {'is_flag': True, 'short': 'e', 'default': False, 'help': 'Extract complete URLs'},
		'status_check': {'is_flag': True, 'short': 'k', 'default': True, 'help': 'Check status codes of found URLs'},
		'concurrency': {'type': int, 'short': 'c', 'default': 20, 'help': 'Number of concurrent requests'},
		'pattern_file': {'type': str, 'short': 't', 'help': 'Path to custom regex pattern YAML file'},
	}
	opt_key_map = {
		'secrets': 's',
		'links': 'l',
		'complete': 'e',
		'status_check': 'k',
		'concurrency': 'c',
		'pattern_file': 't',
	}
	item_loaders = [JSONSerializer()]
	install_version = 'v1.1.0'
	install_cmd = 'go install -v github.com/channyein1337/jsleak@[install_version]'
	github_handle = 'channyein1337/jsleak'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'io'

	@staticmethod
	def on_json_loaded(self, item):
		"""Process JSON output from jsleak."""
		# jsleak returns different types of data
		item_type = item.get('type', '')
		url = item.get('url', '')
		
		if item_type == 'secret':
			# Secret found
			name = item.get('name', 'unknown_secret')
			match_value = item.get('match', '')
			extra_data = {
				'content': match_value,
				'url': url,
			}
			
			# Add any additional fields from jsleak
			for key in ['confidence', 'line', 'pattern']:
				if key in item:
					extra_data[key] = item[key]
			
			yield Tag(
				category='secret',
				name=name.lower().replace(' ', '_').replace('-', '_'),
				match=url,
				extra_data=extra_data
			)
		
		elif item_type == 'link' or item_type == 'endpoint':
			# URL/endpoint found
			found_url = item.get('link', item.get('endpoint', ''))
			if found_url:
				status_code = item.get('status', 0)
				yield Url(
					url=found_url,
					status_code=status_code,
					extra_data={'source_url': url}
				)
		
		elif 'secret' in item or 'match' in item:
			# Fallback for simple secret format
			match_value = item.get('match', item.get('secret', ''))
			name = item.get('name', item.get('type', 'leaked_secret'))
			
			yield Tag(
				category='secret',
				name=name.lower().replace(' ', '_').replace('-', '_'),
				match=url or 'unknown',
				extra_data={'content': match_value, 'url': url}
			)
		
		elif 'url' in item or 'link' in item:
			# Fallback for simple URL format
			found_url = item.get('url', item.get('link', ''))
			if found_url:
				yield Url(url=found_url)
