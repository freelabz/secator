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
		"""Process JSON output from jsleak.
		
		jsleak outputs JSON in format:
		{
			"url": "http://example.com/script.js",
			"pattern": "api_key_regex",
			"matches": ["secret1", "secret2"]
		}
		"""
		url = item.get('url', '')
		pattern = item.get('pattern', 'leaked_secret')
		matches = item.get('matches', [])
		
		# Create a Tag for each match found
		for match in matches:
			if not match:
				continue
			
			# Clean up pattern name to use as tag name
			name = pattern.lower().replace(' ', '_').replace('-', '_')
			
			yield Tag(
				category='secret',
				name=name,
				match=url,
				extra_data={
					'content': match,
					'pattern': pattern
				}
			)
