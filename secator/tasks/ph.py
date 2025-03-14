from secator.decorators import task
from secator.definitions import (NAME, EXTRA_DATA)
from secator.output_types import Tag
from secator.tasks._categories import Tagger


@task()
class ph(Tagger):
	"""Fast and customisable vulnerability scanner based on simple YAML based DSL."""
	cmd = f'ph'
	file_flag = '-l'
	input_flag = '-f'
	json_flag = '-jsonl'
	opts = {
		'p': {'type': str, 'short': 'p', 'help': 'Patterns'},
	}
	output_types = [Tag]
	output_map = {
		Tag: {
			NAME: 'regex_name',
			'match': 'match',
			EXTRA_DATA: lambda x: {'file_path': x['file_path'], 'line_number': str(x['line_number']), 'char_position': str(x['char_position']), 'line': x['line'], 'regex_path': x['regex_path']}
		},
	}
	ignore_return_code = True
	install_cmd = 'go install -v github.com/freelabz/ph/cmd/ph@latest'
	proxychains = False
	proxy_socks5 = False 
	proxy_http = False
	profile = 'cpu'