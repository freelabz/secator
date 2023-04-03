from secsy.definitions import OPT_PIPE_INPUT, URL
from secsy.output_types import Tag
from secsy.runners import Command


class gf(Command):
	"""Wrapper around grep, to help you grep for things."""
	cmd = 'gf'
	file_flag = OPT_PIPE_INPUT
	input_flag = OPT_PIPE_INPUT
	opts = {
		'pattern': {'type': str, 'required': True, 'help': 'Pattern names to match against (comma-delimited)'}
	}
	opt_key_map = {
		'pattern': ''
	}
	input_type = URL
	install_cmd = 'go install -v github.com/tomnomnom/gf@latest'
	output_types = [Tag]
	item_loader = lambda self, line: {'match': line, 'extra_data': {'pattern': self.get_opt_value('pattern')}}  # noqa: E731
