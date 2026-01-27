from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Domain
from secator.runners import Command
from secator.serializers import JSONSerializer


@task()
class whois(Command):
	"""The whois tool from likexian retrieves domain registration information in JSON format."""
	cmd = 'whois'
	input_flag = None
	json_flag = '-j'
	input_chunk_size = 1
	input_types = [HOST]
	output_types = [Domain]
	item_loaders = [JSONSerializer()]
	version_flag = '-V'
	install_version = 'v1.15.7'
	install_cmd = 'go install -v github.com/likexian/whois/cmd/whois@[install_version]'
	install_github_bin = False
	github_handle = 'likexian/whois'

	@staticmethod
	def on_json_loaded(self, item):
		domain_info = item.get('domain', {})
		registrar_info = item.get('registrar', {})
		registrant_info = item.get('registrant', {})
		administrative_info = item.get('administrative', {})
		technical_info = item.get('technical', {})
		
		# Build extra_data with all remaining information
		extra_data = {
			'domain_id': domain_info.get('id', ''),
			'punycode': domain_info.get('punycode', ''),
			'whois_server': domain_info.get('whois_server', ''),
			'status': domain_info.get('status', []),
			'name_servers': domain_info.get('name_servers', []),
			'registrar_id': registrar_info.get('id', ''),
			'registrar_phone': registrar_info.get('phone', ''),
			'registrar_email': registrar_info.get('email', ''),
			'registrar_url': registrar_info.get('referral_url', ''),
			'registrant': {
				'id': registrant_info.get('id', ''),
				'name': registrant_info.get('name', ''),
				'organization': registrant_info.get('organization', ''),
				'street': registrant_info.get('street', ''),
				'city': registrant_info.get('city', ''),
				'postal_code': registrant_info.get('postal_code', ''),
				'country': registrant_info.get('country', ''),
				'phone': registrant_info.get('phone', ''),
				'fax': registrant_info.get('fax', ''),
				'email': registrant_info.get('email', ''),
			},
			'administrative': {
				'id': administrative_info.get('id', ''),
				'name': administrative_info.get('name', ''),
				'organization': administrative_info.get('organization', ''),
				'street': administrative_info.get('street', ''),
				'city': administrative_info.get('city', ''),
				'province': administrative_info.get('province', ''),
				'postal_code': administrative_info.get('postal_code', ''),
				'country': administrative_info.get('country', ''),
				'phone': administrative_info.get('phone', ''),
				'fax': administrative_info.get('fax', ''),
				'email': administrative_info.get('email', ''),
			},
			'technical': {
				'id': technical_info.get('id', ''),
				'name': technical_info.get('name', ''),
				'organization': technical_info.get('organization', ''),
				'street': technical_info.get('street', ''),
				'city': technical_info.get('city', ''),
				'province': technical_info.get('province', ''),
				'postal_code': technical_info.get('postal_code', ''),
				'country': technical_info.get('country', ''),
				'phone': technical_info.get('phone', ''),
				'fax': technical_info.get('fax', ''),
				'email': technical_info.get('email', ''),
			},
		}
		
		# Parse dates - they come in ISO format like "2010-06-14T07:50:29Z"
		creation_date = domain_info.get('created_date', '')
		if creation_date:
			# Convert from ISO format to expected format "YYYY-MM-DD HH:MM:SS"
			creation_date = creation_date.replace('T', ' ').replace('Z', '')
		
		expiration_date = domain_info.get('expiration_date', '')
		if expiration_date:
			# Convert from ISO format to expected format "YYYY-MM-DD HH:MM:SS"
			expiration_date = expiration_date.replace('T', ' ').replace('Z', '')
		
		yield Domain(
			domain=domain_info.get('domain', ''),
			registrar=registrar_info.get('name', ''),
			creation_date=creation_date,
			expiration_date=expiration_date,
			registrant=registrant_info.get('organization', ''),
			extra_data=extra_data
		)
