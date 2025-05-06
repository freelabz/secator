import os
import yaml
import json

from secator.decorators import task
from secator.definitions import (OUTPUT_PATH, RATE_LIMIT, THREADS, DELAY, TIMEOUT, METHOD, WORDLIST,
								 HEADER, URL, FOLLOW_REDIRECT)
from secator.output_types import Info
from secator.runners import Command
from secator.tasks._categories import OPTS
from secator.utils import process_wordlist


@task()
class whois(Command):
	"""The whois tool retrieves registration information about domain names and IP addresses."""
	cmd = 'whoisdomain'
	input_flag = '-d'
	json_flag = '--json'


	install_pre = {
		'apt|pacman|brew': ['whois'],
		'apk': ['whois'],
	}

	install_version = '1.20230906.1'
	install_cmd = 'pipx install whoisdomain==[install_version] --force'
	install_github_handle = 'mboot-github/WhoisDomain'

	@staticmethod
	def item_loader(self, line):
		data = json.loads(line)
		yield Info(
					message=data['name'],
				)