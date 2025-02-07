import re

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (CVES, EXTRA_DATA, ID, MATCHED_AT, NAME,
								 PROVIDER, REFERENCE, TAGS, OPT_NOT_SUPPORTED)
from secator.output_types import Exploit
from secator.runners import Command
from secator.serializers import JSONSerializer


SEARCHSPLOIT_TITLE_REGEX = re.compile(r'^((?:[a-zA-Z\-_!\.()]+\d?\s?)+)\.?\s*(.*)$')


@task()
class searchsploit(Command):
	"""Exploit searcher based on ExploitDB."""
	cmd = 'searchsploit'
	input_flag = None
	json_flag = '--json'
	version_flag = OPT_NOT_SUPPORTED
	opts = {
		'strict': {'short': 's', 'is_flag': True, 'default': False, 'help': 'Strict match'}
	}
	opt_key_map = {}
	item_loaders = [JSONSerializer()]
	output_types = [Exploit]
	output_map = {
		Exploit: {
			NAME: 'Title',
			ID: 'EDB-ID',
			PROVIDER: lambda x: 'EDB',
			CVES: lambda x: [c for c in x['Codes'].split(';') if c.startswith('CVE-')],
			REFERENCE: lambda x: f'https://exploit-db.com/exploits/{x["EDB-ID"]}',
			TAGS: lambda x: searchsploit.tags_extractor(x),
			EXTRA_DATA: lambda x: {
				k.lower().replace('date_', ''): v for k, v in x.items() if k not in ['Title', 'EDB-ID', 'Codes', 'Tags', 'Source'] and v != ''  # noqa: E501
			}
		}
	}
	install_pre = {
		'apk': ['ncurses']
	}
	install_cmd = (
		f'git clone  --depth 1 --single-branch https://gitlab.com/exploit-database/exploitdb.git {CONFIG.dirs.share}/exploitdb || true && '  # noqa: E501
		f'ln -sf $HOME/.local/share/exploitdb/searchsploit {CONFIG.dirs.bin}/searchsploit'
	)
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	input_chunk_size = 1
	profile = 'io'

	@staticmethod
	def tags_extractor(item):
		tags = []
		for tag in item['Tags'].split(','):
			_tag = '_'.join(
				tag.lower().replace('-', '_',).replace('(', '').replace(')', '').split(' ')
			)
			if not _tag:
				continue
			tags.append(tag)
		return tags

	@staticmethod
	def before_init(self):
		if len(self.inputs) == 0:
			return
		_in = self.inputs[0]
		self.matched_at = None
		if '~' in _in:
			split = _in.split('~')
			self.matched_at = split[0]
			self.inputs[0] = split[1]
		self.inputs[0] = self.inputs[0].replace('httpd', '').replace('/', ' ')

	@staticmethod
	def on_item_pre_convert(self, item):
		if self.matched_at:
			item[MATCHED_AT] = self.matched_at
		return item

	@staticmethod
	def on_item(self, item):
		match = SEARCHSPLOIT_TITLE_REGEX.match(item.name)
		# if not match:
		# 	self._print(f'[bold red]{item.name} ({item.reference}) did not match SEARCHSPLOIT_TITLE_REGEX. Please report this issue.[/]')  # noqa: E501
		if match:
			group = match.groups()
			product = '-'.join(group[0].strip().split(' '))
			if len(group[1]) > 1:
				try:
					versions, title = tuple(group[1].split(' - '))
					item.name = title
					product_info = [f'{product.lower()} {v.strip()}' for v in versions.split('/')]
					item.tags = product_info + item.tags
				except ValueError:
					item.name = item.name.split(' - ')[-1]
					item.tags = [product.lower()]
					pass
			# else:
			# 	self._print(f'[bold red]{item.name} ({item.reference}) did not quite match SEARCHSPLOIT_TITLE_REGEX. Please report this issue.[/]')  # noqa: E501
		input_tag = '-'.join(self.inputs[0].replace('\'', '').split(' '))
		item.tags = [input_tag] + item.tags
		return item
