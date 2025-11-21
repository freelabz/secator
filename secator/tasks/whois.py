from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Domain
from secator.runners import Command
from secator.serializers import JSONSerializer


@task()
class whois(Command):
	"""The whois tool retrieves registration information about domain names and IP addresses."""
	cmd = 'whoisdomain'
	input_flag = '-d'
	json_flag = '--json'
	input_chunk_size = 1
	input_types = [HOST]
	output_types = [Domain]
	item_loaders = [JSONSerializer()]
	version_flag = '-V'
	install_version = '1.20230906.1'
	install_cmd_pre = {'*': ['whois']}
	install_cmd = 'pipx install whoisdomain==[install_version] --force'
	install_github_bin = False
	github_handle = 'mboot-github/WhoisDomain'

	@staticmethod
	def on_json_loaded(self, item):
		yield Domain(
			domain=item['name'],
			registrar=item['registrar'],
			creation_date=item['creation_date'],
			expiration_date=item['expiration_date'],
			registrant=item['registrant'],
			extra_data={'emails': item['emails']}
		)
