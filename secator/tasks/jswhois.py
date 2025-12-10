from secator.decorators import task
from secator.runners import Command
from secator.definitions import HOST
from secator.output_types import Tag
from secator.serializers import JSONSerializer


@task()
class jswhois(Command):
	"""WHOIS in JSON format"""
	cmd = 'jswhois'
	input_types = [HOST]
	output_types = [Tag]
	item_loaders = [JSONSerializer(list=True)]
	tags = ['domain', 'info']
	input_flag = None
	file_flag = None
	input_chunk_size = 1
	version_flag = '-V'
	install_version = '69af013b99d49191c9674cde2e2b57986f6b6bf8'
	install_cmd = 'go install -v github.com/jschauma/jswhois@[install_version]'
	install_github_bin = False
	github_handle = 'jschauma/jswhois'

	@staticmethod
	def on_json_loaded(self, item):
		last_chain = item['chain'][-1]
		last_elem = item[last_chain]
		raw = last_elem.pop('raw')
		tag = Tag(
			name='whois',
			category='info',
			match=self.inputs[0],
			value=raw,
			extra_data={'chain': last_chain}
		)
		yield tag
