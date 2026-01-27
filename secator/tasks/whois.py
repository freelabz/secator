from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Domain, Warning
from secator.runners import Command

import json


@task()
class whois(Command):
	"""The whois tool from likexian retrieves domain registration information in JSON format."""
	cmd = 'whois-go'
	input_flag = None
	json_flag = None
	input_chunk_size = 1
	input_types = [HOST]
	output_types = [Domain]
	version_flag = '-V'
	install_version = 'v1.15.7'
	install_cmd = 'go install -v github.com/likexian/whois/cmd/whois@[install_version]'
	install_github_bin = False
	install_binary_name = 'whois-go'  # rename to avoid conflicts with whois binary
	github_handle = 'likexian/whois'
	ignore_return_code = True

	@staticmethod
	def on_cmd(self):
		self.cmd = self.cmd.replace('whois-go', 'whois-go -j')

	@staticmethod
	def on_end(self):
		try:
			item = json.loads(self.output)
		except json.JSONDecodeError:
			message = self.output.replace('whoisparser: ', '')
			message += ' for ' + self.inputs[0]
			self.add_result(Warning(message=message))
			return
		domain_info = item.get('domain', {})
		registrar_info = item.get('registrar', {})
		registrant_info = item.get('registrant', {})
		administrative_info = item.get('administrative', {})
		technical_info = item.get('technical', {})
		creation_date = domain_info.get('created_date', '')
		expiration_date = domain_info.get('expiration_date', '')
		updated_date = domain_info.get('updated_date', '')
		statuses = domain_info.get('status', [])
		extra_data = {
			'domain_id': domain_info.get('id', ''),
			'punycode': domain_info.get('punycode', ''),
			'whois_server': domain_info.get('whois_server', ''),
			'name_servers': domain_info.get('name_servers', []),
		}
		self.add_result(Domain(
			domain=domain_info.get('domain', ''),
			creation_date=creation_date,
			expiration_date=expiration_date,
			updated_date=updated_date,
			status=statuses,
			registrar=registrar_info.get('name', ''),
			registrar_info=registrar_info,
			registrant=registrant_info.get('organization', ''),
			registrant_info=registrant_info,
			administrative_info=administrative_info,
			technical_info=technical_info,
			extra_data=extra_data
		))
