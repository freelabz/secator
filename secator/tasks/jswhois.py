from secator.decorators import task
from secator.runners import Command
from secator.definitions import HOST
from secator.output_types import Domain
from secator.serializers import JSONSerializer


@task()
class jswhois(Command):
	"""WHOIS in JSON format"""
	cmd = 'jswhois'
	input_types = [HOST]
	output_types = [Domain]
	item_loaders = [JSONSerializer(list=True)]
	input_flag = None
	file_flag = None
	input_chunk_size = 1
	version_flag = '-V'
	install_version = '69af013b99d49191c9674cde2e2b57986f6b6bf8'
	install_cmd = 'go install -v github.com/jschauma/jswhois@[install_version]'
	install_github_bin = False
	github_handle = 'jschauma/jswhois'

	@staticmethod
	def on_json_loaded(self, item):
		# Get the last element in the chain (most specific whois server)
		last_chain = item['chain'][-1]
		last_elem = item[last_chain]
		
		# Extract domain information from the last element
		domain_info = last_elem.get('domain', {})
		raw = last_elem.get('raw', '')
		
		# Extract domain name (from domain_info or fallback to input)
		domain_name = domain_info.get('domain') or self.inputs[0]
		
		# Extract registrar
		registrar = domain_info.get('registrar') or last_elem.get('registrar', {}).get('registrar', '')
		
		# Extract creation date
		creation_date = domain_info.get('created', '')
		if creation_date and 'T' in creation_date:
			creation_date = f'{creation_date.split("T")[0]} {creation_date.split("T")[1].split("Z")[0]}'
		
		# Extract expiration date
		expiration_date = domain_info.get('Expiry Date', '')
		if expiration_date and 'T' in expiration_date:
			expiration_date = expiration_date.split('T')[0] + ' ' + expiration_date.split('T')[1].split('Z')[0]
		
		# Extract registrant (from nic-hdl or domain holder)
		registrant = ''
		nic_hdl = last_elem.get('nic-hdl', {})
		if nic_hdl:
			registrant = nic_hdl.get('contact', '') or nic_hdl.get('nic-hdl', '')
		if not registrant:
			registrant = domain_info.get('holder-c', '')
		
		# Extract emails from various sources
		emails = []
		if nic_hdl and 'e-mail' in nic_hdl:
			emails.append(nic_hdl['e-mail'])
		if last_elem.get('registrar', {}).get('e-mail'):
			emails.append(last_elem['registrar']['e-mail'])
		
		# Build extra_data with additional information
		extra_data = {
			'chain': item['chain'],
			'whois_server': last_chain,
			'raw': raw,
			'emails': emails,
			'status': domain_info.get('status', ''),
			'eppstatus': domain_info.get('eppstatus', ''),
			'registrar_info': last_elem.get('registrar', {}),
			'nic_hdl': nic_hdl,
			'nserver': domain_info.get('nserver', {}) or last_elem.get('nserver', {}),
		}
		
		# Add key1-tag if present (DNSSEC)
		if 'key1-tag' in last_elem:
			extra_data['key1-tag'] = last_elem['key1-tag']
		
		yield Domain(
			domain=domain_name,
			registrar=registrar,
			creation_date=creation_date,
			expiration_date=expiration_date,
			registrant=registrant,
			extra_data=extra_data
		)
