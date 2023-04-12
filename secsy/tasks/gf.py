from secsy.definitions import OPT_PIPE_INPUT, URL
from secsy.output_types import Tag
from secsy.tasks._categories import Tagger


class gf(Tagger):
	"""Wrapper around grep, to help you grep for things."""
	cmd = 'gf'
	file_flag = OPT_PIPE_INPUT
	input_flag = OPT_PIPE_INPUT
	opts = {
		'pattern': {'type': str, 'help': 'Pattern names to match against (comma-delimited)'}
	}
	opt_key_map = {
		'pattern': ''
	}
	input_type = URL
	install_cmd = (
		'go install -v github.com/tomnomnom/gf@latest && '
		'git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf || true'
	)
	output_types = [Tag]
	item_loader = lambda self, line: {'match': line, 'name': self.get_opt_value('pattern')}  # noqa: E731
	proxychains = False

	@staticmethod
	def on_item_converted(self, item):
		item.extra_data = {'source': 'url'}
		return item
