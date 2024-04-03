import json
import os

import validators

from secator.decorators import task
from secator.definitions import (DELAY, LIMIT, OPT_NOT_SUPPORTED, PROXY,
								 RATE_LIMIT, RETRIES, SCREENSHOT, TEMP_FOLDER,
								 THREADS, TIMEOUT)
from secator.output_types import Ip, Subdomain, Url, UserAccount
from secator.tasks._categories import ReconUser
from secator.utils import get_file_timestamp


@task()
class theHarvester(ReconUser):
	"""theHarvester is a tool designed to be used during the reconnaissance stage."""
	cmd = 'theHarvester'
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
		#prev = self.print_item_count
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
			hosts = data.get('hosts', [])
			#asns = data.get('asns', [])
			interesting_urls = data.get('interesting_urls', [])
			ips = data.get('ips', [])
			emails = data.get('emails', [])
			target = self.targets[0]

			for ip in ips:
				yield Ip(ip=ip, host=target)
			for host in hosts:
				parts = host.split(':')
				if len(parts) == 1:
					continue
				if len(parts) > 2:
					host = parts[0]
					ip = ':'.join(parts[1:-1])
				else:
					host, ip = tuple(parts)
				if validators.ip_address.ipv4(ip) or validators.ip_address.ipv6(ip):
					yield Ip(ip=ip, host=host)
				yield Subdomain(host=host, domain=target)
			for interesting_url in interesting_urls:
				yield Url(url=interesting_url)
			for email in emails:
				yield UserAccount(email=emails)


install_cmd = ('git clone https://github.com/laramies/theHarvester || True &&'
				'cd theHarvester || python3 -m pip install -r requirements/base.txt')
socks5_proxy = True
