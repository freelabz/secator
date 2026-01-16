from datetime import datetime

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
	def _parse_iso_date(date_str: str) -> str:
		"""
		Parse ISO 8601 date string and convert to format expected by Domain output type.
		Handles timezone-aware dates and microseconds.

		Args:
			date_str: ISO 8601 date string (e.g., "2026-03-06T16:42:17.573554Z")

		Returns:
			str: Formatted date string in format "%Y-%m-%d %H:%M:%S" or empty string if invalid
		"""
		if not date_str:
			return ''

		try:
			# Handle ISO format with timezone (Z or +HH:MM)
			# Replace Z with +00:00 for fromisoformat compatibility
			normalized_date = date_str.replace('Z', '+00:00')
			# Parse ISO format with timezone support
			dt = datetime.fromisoformat(normalized_date)
			# Format to expected format: "%Y-%m-%d %H:%M:%S"
			return dt.strftime("%Y-%m-%d %H:%M:%S")
		except (ValueError, AttributeError):
			# Fallback to manual parsing if fromisoformat fails
			if 'T' in date_str:
				date_part = date_str.split('T')[0]
				time_part = date_str.split('T')[1].split('Z')[0].split('+')[0].split('-')[0]
				# Remove microseconds if present
				if '.' in time_part:
					time_part = time_part.split('.')[0]
				return f"{date_part} {time_part}"
			return ''

	@staticmethod
	def on_json_loaded(self, item):
		# Get the last element in the chain (most specific whois server)
		last_chain = item['chain'][-1]
		last_elem = item[last_chain]

		# Extract domain information from the last element
		domain_info = last_elem.get('domain', {})
		raw = last_elem.get('raw', '')

		# Check for malformed request and return early if found
		if 'Malformed request' in raw:
			return

		# Extract domain name (from domain_info or fallback to input)
		domain_name = domain_info.get('domain') or self.inputs[0]

		# Extract registrar
		registrar = domain_info.get('registrar') or last_elem.get('registrar', {}).get('registrar', '')

		# Extract and parse dates using helper method
		creation_date = jswhois._parse_iso_date(domain_info.get('created', ''))
		expiration_date = jswhois._parse_iso_date(domain_info.get('Expiry Date', ''))
		last_update = jswhois._parse_iso_date(domain_info.get('last-update', ''))

		# Extract registrant (from nic-hdl or domain holder)
		registrant = ''
		nic_hdl = last_elem.get('nic-hdl', {})

		# Handle case where nic-hdl is a list (multiple contacts)
		if isinstance(nic_hdl, list) and len(nic_hdl) > 0:
			# Use the first nic-hdl in the list for registrant
			nic_hdl = nic_hdl[0]

		# Handle case where nic-hdl is a dict
		if isinstance(nic_hdl, dict):
			registrant = nic_hdl.get('contact', '') or nic_hdl.get('nic-hdl', '')

		if not registrant:
			registrant = domain_info.get('holder-c', '')

		# Extract admin-c and tech-c from domain_info
		admin_c = domain_info.get('admin-c', '')
		tech_c = domain_info.get('tech-c', '')

		# Extract emails from various sources
		emails = []
		if isinstance(nic_hdl, dict) and 'e-mail' in nic_hdl:
			emails.append(nic_hdl['e-mail'])
		if last_elem.get('registrar', {}).get('e-mail'):
			emails.append(last_elem['registrar']['e-mail'])

		# Function to recursively remove 'raw' fields from JSON structure
		def remove_raw_fields(obj):
			if isinstance(obj, dict):
				return {k: remove_raw_fields(v) for k, v in obj.items() if k != 'raw'}
			elif isinstance(obj, list):
				return [remove_raw_fields(item) for item in obj]
			return obj

		# Clean jswhois_full by removing all 'raw' fields before storing
		cleaned_jswhois_full = remove_raw_fields(item)

		# Build extra_data with additional information
		# Store the full jswhois JSON response for complete data access (without raw fields)
		extra_data = {
			'chain': item['chain'],
			'whois_server': last_chain,
			'emails': emails,
			'status': domain_info.get('status', ''),
			'eppstatus': domain_info.get('eppstatus', ''),
			'registrar_info': last_elem.get('registrar', {}),
			'nic_hdl': nic_hdl,
			'nserver': domain_info.get('nserver', {}) or last_elem.get('nserver', {}),
			'admin_c': admin_c,
			'tech_c': tech_c,
			'last_update': last_update,
			'domain_info': domain_info,
			'jswhois_full': cleaned_jswhois_full,
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
