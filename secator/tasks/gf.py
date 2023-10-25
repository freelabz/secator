from secator.decorators import task
from secator.definitions import OPT_PIPE_INPUT, URL
from secator.output_types import Tag
from secator.tasks._categories import Tagger


@task()
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

	@staticmethod
	def item_loader(self, line):
		return {'match': line, 'name': self.get_opt_value('pattern').rstrip() + ' pattern'}  # noqa: E731,E501

	@staticmethod
	def on_item(self, item):
		item.extra_data = {'source': 'url'}
		return item
