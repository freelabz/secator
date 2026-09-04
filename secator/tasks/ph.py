from secator.decorators import task
from secator.definitions import (URL, STRING, OPT_PIPE_INPUT)
from secator.output_types import Tag
from secator.tasks._categories import Tagger
from secator.serializers import JSONSerializer


@task()
class ph(Tagger):
	"""Fast and customisable vulnerability scanner based on simple YAML based DSL."""
	cmd = 'ph'
	input_types = [URL, STRING]
	file_flag = OPT_PIPE_INPUT
	input_flag = OPT_PIPE_INPUT
	json_flag = '-jsonl -sc'
	item_loaders = [JSONSerializer()]
	opts = {
		'p': {'type': str, 'short': 'p', 'help': 'Patterns'},
	}
	output_types = [Tag]
	ignore_return_code = True
	install_version = 'v0.1.1'
	install_cmd = 'go install -v github.com/freelabz/ph/cmd/ph@[install_version]'
	github_handle = 'freelabz/ph'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'cpu'

	@staticmethod
	def on_json_loaded(self, item):
		match = item['match']
		config = item['config']
		name = config['name']
		match_str = match['context']
		value = match['value']
		if not name or not match_str or not value:
			return
		yield Tag(
			name=name,
			match=match_str,
			value=value,
			extra_data={
				'input_path': item['input_path'],
				'line_number': match['line_number'],
				'char_position': match['char_position'],
				'context': match['context'],
				'pattern': match['pattern'],
				'regex_path': config['path'],
			}
		)
