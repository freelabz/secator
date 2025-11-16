import os
import tempfile
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, HEADER, PROXY, HOST, TIMEOUT, OPT_PIPE_INPUT)
from secator.output_types import Tag, Info, Error
from secator.serializers import JSONSerializer
from secator.tasks._categories import OPTS


@task()
class jswhois(Command):
	"""WHOIS in JSON format"""
	cmd = 'jswhois'
	input_types = [HOST]
	output_types = [Tag]
	item_loaders = [JSONSerializer()]
	tags = ['domain', 'info']
	input_flag = None
	file_flag = None
	install_version = 'latest'
	install_cmd = 'go install -v github.com/jschauma/jswhois@[install_version]'
	# install_github_handle = 'jschauma/jswhois'

	@staticmethod
	def on_json_loaded(self, item):
		last_chain = item['chain'][-1]
		last_elem = item[last_chain]
		raw = last_elem.pop('raw')
		tag = Tag(
			name=f'{self.inputs[0]} WHOIS',
			category='whois',
			match=self.inputs[0],
			extra_data={'info': raw, 'chain': last_chain}
		)
		yield tag
