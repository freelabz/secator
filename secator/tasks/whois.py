import json

from secator.decorators import task
from secator.output_types import Domain
from secator.runners import Command



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
		try:
			data = json.loads(line)
			yield Domain(
						domain=data['name'],
						registrar=data['registrar'],
						creation_date=data['creation_date'],
						expiration_date=data['expiration_date'],
						registrant=data['registrant'],
						extra_data={'emails':data['emails']}
					)
		except (json.JSONDecodeError, KeyError) as e:  
			# Log error or skip malformed lines  
			pass  
		