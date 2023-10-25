from secator.decorators import task
from secator.runners import Command
from secator.output_types import Exploit
from secator.definitions import (
	ID, NAME, PROVIDER, CVES, MATCHED_AT, REFERENCE, EXTRA_DATA
)


@task()
class searchsploit(Command):
	"""Exploit-DB command line search tool."""
	cmd = 'searchsploit'
	input_flag = None
	json_flag = '--json'
	opts = {
		'strict': {'short': 's', 'is_flag': True, 'default': False, 'help': 'Strict match'}
	}
	opt_key_map = {}
	output_types = [Exploit]
	output_map = {
		Exploit: {
			NAME: lambda x: '-'.join(x['Title'].split('-')[1:]).strip(),
			PROVIDER: lambda x: 'EDB',
			ID: 'EDB-ID',
			CVES: lambda x: [c for c in x['Codes'].split(';') if c.startswith('CVE-')],
			REFERENCE: lambda x: f'https://exploit-db.com/exploits/{x["EDB-ID"]}',
			EXTRA_DATA: lambda x: {'verified': x['Verified']}
		}
	}
	install_cmd = 'sudo apt -y install exploitdb'
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	input_chunk_size = 1
	profile = 'io'

	@staticmethod
	def before_init(self):
		_in = self.input
		self.matched_at = None
		if '~' in _in:
			split = _in.split('~')
			self.matched_at = split[0]
			self.input = split[1]
		self.input = self.input.replace('httpd', '').replace('/', ' ')

	@staticmethod
	def on_item_pre_convert(self, item):
		if self.matched_at:
			item[MATCHED_AT] = self.matched_at
		return item
