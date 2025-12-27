import json
import os

from secator.decorators import task
from secator.definitions import OUTPUT_PATH, URL
from secator.output_types import Tag, Info, Error
from secator.tasks._categories import Tagger


@task()
class evilwaf(Tagger):
	"""Advanced WAF bypass tool testing various bypass techniques."""
	cmd = 'python3'
	input_types = [URL]
	output_types = [Tag]
	tags = ['waf', 'bypass', 'scan']
	input_flag = '-d'
	file_flag = None
	opt_prefix = '--'
	encoding = 'ansi'
	opts = {
		'output': {'type': str, 'short': 'o', 'help': 'Output file for results'},
		'update': {'is_flag': True, 'short': 'u', 'default': False, 'help': 'Update EvilWAF'},
	}
	opt_key_map = {
		'output': 'output'
	}
	install_cmd = 'git clone https://github.com/matrixleons/evilwaf.git ~/.local/share/evilwaf && pip3 install -r ~/.local/share/evilwaf/requirements.txt'
	install_github_bin = False
	github_handle = 'matrixleons/evilwaf'
	proxy_http = False

	@staticmethod
	def on_init(self):
		# Modify cmd to point to evilwaf.py script
		evilwaf_path = os.path.expanduser('~/.local/share/evilwaf/evilwaf.py')
		self.cmd = f'python3 {evilwaf_path}'

	@staticmethod
	def on_cmd(self):
		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		# Add output flag if not already specified
		if '-o' not in self.cmd and '--output' not in self.cmd:
			self.cmd += f' -o {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		# Skip parsing if update mode
		update_mode = self.get_opt_value('update')
		if update_mode:
			return

		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		
		try:
			with open(self.output_path, 'r') as f:
				results = json.load(f)
		except json.JSONDecodeError as e:
			yield Error(message=f'Failed to parse JSON output: {e}')
			return

		# Process results by technique category
		for technique, bypasses in results.items():
			if not bypasses or not isinstance(bypasses, list):
				continue
			
			for bypass_item in bypasses:
				# Determine the value based on the bypass item type
				if isinstance(bypass_item, dict):
					# For dictionary items, use a key like 'ip', 'subdomain', 'header', etc.
					value = bypass_item.get('ip') or bypass_item.get('subdomain') or bypass_item.get('header') or str(bypass_item)
					extra_data = {**bypass_item, 'technique': technique}
				elif isinstance(bypass_item, str):
					value = bypass_item
					extra_data = {'technique': technique}
				else:
					value = str(bypass_item)
					extra_data = {'technique': technique}
				
				# Get the input URL from the first input
				match_url = self.inputs[0] if self.inputs and len(self.inputs) > 0 else ''
				
				yield Tag(
					category='info',
					name='waf_bypass',
					match=match_url,
					value=value,
					extra_data=extra_data
				)
