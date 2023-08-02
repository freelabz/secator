import os 
import json

from secator.decorators import task
from secator.definitions import (DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, PROXY, LIMIT, SCREENSHOT, OPT_NOT_SUPPORTED, TEMP_FOLDER)
from secator.tasks._categories import ReconUser
from secator.utils import get_file_timestamp
from secator.output_types import UserAccount

@task()
class theHarvester(ReconUser):
	"""theHarvester is a simple to use, yet powerful tool designed to be used during the reconnaissance stage of a red
team assessment or penetration test."""
	cmd = 'theHarvester	'
	file_flag = None
	input_flag = '--domain'
	json_flag = '--filename'
	opt_prefix = '--'
	
	opts = {
		'source': {'type': str, 'short': 'b', 'help': 'bevigil, censys, fullhunt, securityTrails'},
    }
	
	opt_key_map = {
		PROXY: 'proxies',
		LIMIT: 'limit',
		SCREENSHOT: 'screenshot',
		THREADS: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED
	}
	
	@staticmethod
	def on_start(self):
		output_path = self.get_opt_value('output_path')
		if not output_path:
			timestr = get_file_timestamp()
			output_path = f'{TEMP_FOLDER}/theHarvester_{timestr}.json'
		self.output_path = output_path
		self.cmd = self.cmd.replace('--filename', f'--filename {self.output_path}')

def yielder(self):
		prev = self.print_item_count
		self.print_item_count = False
		list(super().yielder())
		if self.return_code != 0:
			return
		self.results = []
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				data = json.load(f)
			if self.print_orig:  # original h8mail output
				yield data
				return
			targets = data['hosts']
			for target in targets:
				email = target['target']
				target_data = target['data']
				if not len(target_data) > 0:
					continue
				entries = target_data[0]
				for entry in entries:
					source, site_name = tuple(entry.split(':'))
					yield UserAccount(**{
						"site_name": site_name,
						"username": email.split('@')[0],
						"email": email,
						"extra_data": {
							'source': source
						},
					})


	install_cmd = ('git clone https://github.com/laramies/theHarvester || True &&'
				'cd theHarvester || python3 -m pip install -r requirements/base.txt')
	socks5_proxy = True