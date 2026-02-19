import logging

from datetime import datetime
from typing import Any, Dict, Iterator, List, Tuple

from secator.decorators import task
from secator.runners import Command
from secator.definitions import HOST
from secator.output_types import Domain
from secator.serializers import JSONSerializer
from secator.utils import debug, extract_domain_info

logger = logging.getLogger(__name__)


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
		# Collect candidates from all WHOIS servers (structured + raw-parsed)
		debug('Collect WHOIS candidates')
		candidates = jswhois._collect_whois_candidates(item)

		# Early exit only if all sources report a malformed request
		raws = jswhois._collect_raw_texts(item)
		if raws and all('Malformed request' in r for r in raws):
			return

		merged, field_sources, sources_used, primary_server = jswhois._merge_candidates(candidates)

		# Fallback to input if domain name not found
		domain_name = merged.get('domain_name') or (self.inputs[0] if self.inputs else '')

		# Parse dates using helper method
		creation_date = jswhois._parse_iso_date(merged.get('creation_date', ''))
		expiration_date = jswhois._parse_iso_date(merged.get('expiration_date', ''))
		last_update = jswhois._parse_iso_date(merged.get('last_update', ''))

		# Clean jswhois_full by removing all 'raw' fields before storing
		cleaned_jswhois_full = jswhois._strip_raw_fields(item)

		# Extract IANA TLD information
		iana_info = jswhois._extract_iana_info(item)
		iana_status = iana_info.get('status', '')
		alive = isinstance(iana_status, str) and iana_status.strip().upper() == 'ACTIVE'

		domain_info = jswhois._build_domain_info(
			item=item,
			merged=merged,
			candidates=candidates,
			last_update=last_update,
		)

		raw_by_server = jswhois._build_raw_by_server(item)

		whois_payload = jswhois._build_whois_payload(
			item=item,
			merged=merged,
			domain_name=domain_name,
			creation_date=creation_date,
			expiration_date=expiration_date,
			last_update=last_update,
			iana_info=iana_info,
			primary_server=primary_server,
			sources_used=sources_used,
			domain_info=domain_info,
			raw_by_server=raw_by_server,
			cleaned_jswhois_full=cleaned_jswhois_full,
		)

		extra_data = {'whois': whois_payload}

		yield Domain(
			domain=domain_name,
			registrar=merged.get('registrar', ''),
			alive=alive,
			creation_date=creation_date,
			expiration_date=expiration_date,
			registrant=merged.get('registrant', ''),
			extra_data=extra_data
		)

	@staticmethod
	def before_init(self):
		"""Extract root domain from subdomains before calling jswhois."""
		for idx, input_val in enumerate(self.inputs):
			root_domain = extract_domain_info(input_val, domain_only=True)
			if root_domain and root_domain != input_val:
				self.inputs[idx] = root_domain

	@staticmethod
	def _build_domain_info(item: dict, merged: dict, candidates: list, last_update: str) -> Dict[str, Any]:
		"""
		Build a \"domain_info\" fragment for the output payload.

		For FRNIC, prefer the structured \"domain\" dict from the non-raw candidate.
		For other formats, build a FRNIC-like mapping from merged data.
		"""
		if candidates and any(c.get('format_type') == 'FRNIC' for c in candidates):
			for c in candidates:
				if c.get('format_type') == 'FRNIC' and not c.get('from_raw'):
					src = item.get(c.get('server', ''), {})
					if isinstance(src, dict) and isinstance(src.get('domain'), dict):
						return src.get('domain', {})
			return {}

		domain_info: Dict[str, Any] = {}
		if merged.get('domain_name'):
			domain_info['domain'] = merged.get('domain_name')
		if merged.get('registrar'):
			domain_info['registrar'] = merged.get('registrar')
		if merged.get('creation_date'):
			domain_info['created'] = merged.get('creation_date')
		if merged.get('expiration_date'):
			domain_info['Expiry Date'] = merged.get('expiration_date')
		if last_update:
			domain_info['last-update'] = last_update
		if merged.get('status'):
			domain_info['status'] = merged.get('status')
		if merged.get('eppstatus'):
			domain_info['eppstatus'] = merged.get('eppstatus')

		admin_c = merged.get('registry_ids', {}).get('registry_admin_id', '')
		tech_c = merged.get('registry_ids', {}).get('registry_tech_id', '')
		if admin_c:
			domain_info['admin-c'] = admin_c
		if tech_c:
			domain_info['tech-c'] = tech_c

		if merged.get('registrant'):
			domain_info['holder-c'] = merged.get('registrant')
		if merged.get('nserver'):
			domain_info['nserver'] = merged.get('nserver')
		elif merged.get('name_servers'):
			domain_info['nserver'] = {'nserver': merged.get('name_servers')}

		return domain_info

	@staticmethod
	def _build_nserver_dict(name_servers: List[str]) -> dict:
		"""
		Build the "nserver" mapping expected by downstream consumers.
		"""
		return {'nserver': list(set(name_servers))} if name_servers else {}

	@staticmethod
	def _build_raw_by_server(item: dict) -> Dict[str, str]:
		"""
		Return a dict mapping WHOIS server -> raw text.
		"""
		raw_by_server: Dict[str, str] = {}
		for server, server_data in jswhois._iter_chain_servers(item):
			raw = server_data.get('raw', '')
			if isinstance(raw, str) and raw:
				raw_by_server[server] = raw
		return raw_by_server

	@staticmethod
	def _build_whois_payload(
		item: dict,
		merged: dict,
		domain_name: str,
		creation_date: str,
		expiration_date: str,
		last_update: str,
		iana_info: dict,
		primary_server: str,
		sources_used: List[str],
		domain_info: dict,
		raw_by_server: Dict[str, str],
		cleaned_jswhois_full: Any,
	) -> Dict[str, Any]:
		"""
		Build the structured WHOIS payload stored in Domain.extra_data.
		"""
		return {
			'query': item.get('query', ''),
			'chain': item.get('chain', []),
			'servers': {
				'primary': primary_server,
				'used': sources_used,
			},
			'iana': iana_info,
			'registry_ids': merged.get('registry_ids', {}),
			'domain': {
				'name': domain_name,
				'registrar': merged.get('registrar', ''),
				'creation_date': creation_date,
				'expiration_date': expiration_date,
				'updated_date': last_update,
				'statuses': merged.get('domain_statuses', []),
				'name_servers': merged.get('name_servers', []),
				'dnssec': merged.get('dnssec_info', {}),
			},
			'registrar': {
				'name': merged.get('registrar', ''),
				'iana_id': merged.get('registry_ids', {}).get('registrar_iana_id', ''),
				'url': merged.get('registrar_url', ''),
				'whois_server': merged.get('registrar_whois_server', ''),
				'details': merged.get('registrar_info', {}),
			},
			'contacts': {
				'registrant': merged.get('registrant_info', {}),
				'admin': merged.get('admin_info', {}),
				'tech': merged.get('tech_info', {}),
				'extra': merged.get('contacts_extra', {}),
			},
			'emails': merged.get('emails', []),
			'fragments': {
				'domain_info': domain_info,
				'nic_hdl': merged.get('nic_hdl', {}),
				'nserver': merged.get('nserver', {}) or {'nserver': merged.get('name_servers', [])},
			},
			'raw': {
				'by_server': raw_by_server,
			},
			'jswhois': {
				'structured_no_raw': cleaned_jswhois_full,
			},
		}

	@staticmethod
	def _candidate_weight(candidate: dict) -> int:
		"""
		Return a weight used to prioritize some candidates over others.
		"""
		# Prefer the IANA "refer" server, but do not rely solely on it.
		return 10 if candidate.get('prefer') else 0

	@staticmethod
	def _collect_nic_hdl_entries(data) -> list:
		"""
		Collect all FRNIC-like 'nic-hdl' entries from a nested structure.
		"""
		entries = []
		for value in jswhois._collect_values_by_key_deep(data, 'nic-hdl'):
			if isinstance(value, dict):
				entries.append(value)
			elif isinstance(value, list):
				entries.extend(entry for entry in value if isinstance(entry, dict))
		return entries

	@staticmethod
	def _collect_raw_texts(item: dict) -> List[str]:
		"""
		Return all raw WHOIS outputs found in the chain (excluding IANA).
		"""
		raws: List[str] = []
		for _, server_data in jswhois._iter_chain_servers(item):
			raw = server_data.get('raw', '')
			if isinstance(raw, str) and raw:
				raws.append(raw)
		return raws

	@staticmethod
	def _collect_values_by_key_deep(data, key_name: str) -> list:
		"""
		Collect values for all occurrences of a given key in a nested structure.
		"""
		if not key_name:
			return []

		values = []
		target = key_name.lower()
		for node in jswhois._walk(data):
			if not isinstance(node, dict):
				continue
			values.extend(
				value
				for key, value in node.items()
				if isinstance(key, str) and key.lower() == target
			)
		return values

	@staticmethod
	def _collect_whois_candidates(item: dict) -> list:
		"""
		Collect extracted candidates from all WHOIS sources in the chain.

		Each candidate may come from:
		- Structured JSON (direct dict keys)
		- Parsed raw output (raw -> kv -> extraction)

		Args:
			item: Full jswhois JSON response

		Returns:
			list: List of candidates with metadata
		"""
		chain = item.get('chain', [])
		candidates = []

		iana_info = jswhois._extract_iana_info(item)
		prefer_server = iana_info.get('refer') or ''

		for server in chain:
			if server == 'whois.iana.org':
				continue

			server_data = item.get(server, {})
			if not isinstance(server_data, dict):
				continue

			# Structured candidate
			format_type = jswhois._detect_format(server_data)
			debug(f'{server} format_type: {format_type}')
			extracted = jswhois._extract_by_format(server_data, format_type)
			candidates.append({
				'server': server,
				'format_type': format_type,
				'extracted': extracted,
				'from_raw': False,
				'prefer': server == prefer_server,
			})

			# Raw-parsed candidate
			raw = server_data.get('raw')
			if raw and isinstance(raw, str):
				if raw_kv := jswhois._raw_to_kv(raw):
					raw_format = jswhois._detect_format(raw_kv)
					debug(f'{server} raw_format: {raw_format}')
					raw_extracted = jswhois._extract_by_format(raw_kv, raw_format)
					candidates.append({
						'server': server,
						'format_type': raw_format,
						'extracted': raw_extracted,
						'from_raw': True,
						'prefer': server == prefer_server,
					})

		return candidates

	@staticmethod
	def _detect_format(last_elem):
		"""
		Detect the format of WHOIS response.

		Args:
			last_elem: The last element in the WHOIS chain

		Returns:
			str: Format identifier (FRNIC, ICANN_FLAT, ICANN_NESTED, GENERIC)
		"""
		if not isinstance(last_elem, dict):
			return 'GENERIC'

		# Check for FRNIC format (domain dict may be nested)
		if jswhois._find_frnic_domain_dict(last_elem) is not None:
			return 'FRNIC'

		# Check for ICANN flat format (keys directly in last_elem)
		if any(key in last_elem for key in ['Domain Name', 'Registrar', 'Creation Date']):
			return 'ICANN_FLAT'

		# Check for ICANN nested format (has Registrant, Admin, Tech as dicts)
		if any(key in last_elem for key in ['Registrant', 'Admin', 'Tech']):
			return 'ICANN_NESTED'

		return 'GENERIC'

	@staticmethod
	def _extend_unique_emails(emails: List[str], value: object) -> None:
		"""
		Extend an email list with cleaned, unique emails from a value.
		"""
		for raw in jswhois._iter_str_values(value):
			email = jswhois._sanitize_email(raw)
			if email and email not in emails:
				emails.append(email)

	@staticmethod
	def _extract_by_format(data: dict, format_type: str) -> dict:
		"""
		Extract a normalized dict from a source dict based on its detected format.
		Ensures required keys exist to simplify merging.
		"""
		if format_type == 'FRNIC':
			extracted = jswhois._extract_frnic_format(data)
		elif format_type == 'ICANN_FLAT':
			extracted = jswhois._extract_icann_flat_format(data)
		elif format_type == 'ICANN_NESTED':
			extracted = jswhois._extract_icann_nested_format(data)
		else:
			extracted = jswhois._extract_generic_format(data)

		# Normalize missing keys
		extracted.setdefault('registrant_info', {})
		extracted.setdefault('admin_info', {})
		extracted.setdefault('tech_info', {})
		extracted.setdefault('registry_ids', {})
		extracted.setdefault('dnssec_info', {'dnssec': '', 'dnssec_keys': []})
		extracted.setdefault('domain_statuses', [])
		extracted.setdefault('name_servers', [])
		extracted.setdefault('registrar_url', '')
		extracted.setdefault('registrar_whois_server', '')
		extracted.setdefault('registrar_info', {})
		extracted.setdefault('emails', [])
		extracted.setdefault('nic_hdl', {})
		extracted.setdefault('nserver', {})
		extracted.setdefault('status', '')
		extracted.setdefault('eppstatus', '')
		extracted.setdefault('admin_c', '')
		extracted.setdefault('tech_c', '')

		# Contact extras (application purpose, nexus category, etc.)
		contacts_extra = {
			'registrant': jswhois._extract_contacts_extra(data, 'Registrant'),
			'admin': jswhois._extract_contacts_extra(data, 'Admin'),
			'tech': jswhois._extract_contacts_extra(data, 'Tech'),
		}
		if any(contacts_extra.values()):
			extracted['contacts_extra'] = contacts_extra
		else:
			extracted.setdefault('contacts_extra', {})

		return extracted

	@staticmethod
	def _extract_contact_info(data: dict, prefix: str) -> dict:
		"""
		Extract contact information from WHOIS data.

		Args:
			data: Dictionary containing WHOIS data
			prefix: Contact type prefix (Registrant, Admin, Tech)

		Returns:
			dict: Contact information with standardized keys
		"""
		contact = {
			'handle': '',
			'name': '',
			'organization': '',
			'street': [],
			'city': '',
			'state_province': '',
			'postal_code': '',
			'country': '',
			'phone': '',
			'phone_ext': '',
			'fax': '',
			'fax_ext': '',
			'email': '',
		}

		if not isinstance(data, dict):
			return contact

		# Map standard ICANN field names to our contact dict keys
		field_mapping = {
			'name': [f'{prefix} Name', f'{prefix}Name'],
			'organization': [f'{prefix} Organization', f'{prefix}Organization', f'{prefix} Organisation'],
			'street': [f'{prefix} Street', f'{prefix}Street'],
			'city': [f'{prefix} City', f'{prefix}City'],
			'state_province': [f'{prefix} State/Province', f'{prefix}State/Province', f'{prefix} State'],
			'postal_code': [f'{prefix} Postal Code', f'{prefix}PostalCode', f'{prefix} Zip'],
			'country': [f'{prefix} Country', f'{prefix}Country'],
			'phone': [f'{prefix} Phone', f'{prefix}Phone'],
			'phone_ext': [f'{prefix} Phone Ext', f'{prefix}PhoneExt'],
			'fax': [f'{prefix} Fax', f'{prefix}Fax'],
			'fax_ext': [f'{prefix} Fax Ext', f'{prefix}FaxExt'],
			'email': [f'{prefix} Email', f'{prefix}Email'],
		}

		for contact_key, patterns in field_mapping.items():
			value = jswhois._find_field_by_patterns(data, patterns, '')
			if value:
				# Handle street which may be a list
				if contact_key == 'street':
					if isinstance(value, list):
						contact[contact_key] = [s for s in value if s and s != 'REDACTED FOR PRIVACY']
					elif value != 'REDACTED FOR PRIVACY':
						contact[contact_key] = [value]
				else:
					value_str = jswhois._first_str(value)
					# Skip REDACTED values
					if value_str and value_str != 'REDACTED FOR PRIVACY':
						contact[contact_key] = value_str

		return contact

	@staticmethod
	def _extract_contacts_extra(data: dict, prefix: str) -> dict:
		"""
		Extract additional contact metadata (when present) such as:
		- Application Purpose
		- Nexus Category
		"""
		if not isinstance(data, dict):
			return {}
		extra = {}
		app_purpose = jswhois._find_field_by_patterns(data, [f'{prefix} Application Purpose'], '')
		if app_purpose:
			extra['application_purpose'] = app_purpose
		if nexus_category := jswhois._find_field_by_patterns(
			data, [f'{prefix} Nexus Category'], ''
		):
			extra['nexus_category'] = nexus_category
		return extra

	@staticmethod
	def _extract_dnssec_info(data: dict, format_type: str = 'ICANN') -> dict:
		"""
		Extract DNSSEC information from WHOIS data.

		Args:
			data: Dictionary containing WHOIS data
			format_type: 'ICANN' or 'FRNIC'

		Returns:
			dict: DNSSEC information
		"""
		dnssec_info = {
			'dnssec': '',
			'dnssec_keys': [],
		}

		if not isinstance(data, dict):
			return dnssec_info

		if dnssec_value := jswhois._find_field_by_patterns(
			data, ['DNSSEC', 'dnssec', 'Dnssec'], ''
		):
			dnssec_info['dnssec'] = dnssec_value.lower() if isinstance(dnssec_value, str) else str(dnssec_value)

		# FRNIC specific DNSSEC keys
		if format_type == 'FRNIC' and 'key1-tag' in data:
			key_data = data['key1-tag']
			if isinstance(key_data, dict):
				dnssec_info['dnssec_keys'].append({
					'key_tag': key_data.get('key1-tag', ''),
					'algorithm': key_data.get('key1-algo', ''),
					'digest_type': key_data.get('key1-dgst-t', ''),
					'digest': key_data.get('key1-dgst', ''),
				})
				if dnssec_info['dnssec_keys'][0].get('key_tag'):
					dnssec_info['dnssec'] = 'signed'

		return dnssec_info

	@staticmethod
	def _extract_domain_statuses(data: dict) -> list:
		"""
		Extract all domain statuses from WHOIS data.

		Args:
			data: Dictionary containing WHOIS data

		Returns:
			list: List of domain status strings
		"""
		statuses = []

		status_raw = data.get('Domain Status', '')

		if isinstance(status_raw, dict):
			# Domain Status is a dict with status names as keys
			statuses = list(status_raw.keys())
		elif isinstance(status_raw, str):
			# Domain Status is a string, may contain URL
			parts = status_raw.strip().split() if status_raw else []
			status_clean = parts[0] if parts else ''
			if status_clean:
				statuses = [status_clean]
		elif isinstance(status_raw, list):
			# Domain Status is a list
			for s in status_raw:
				if isinstance(s, str):
					parts = s.strip().split()
				elif val := str(s).strip():
					parts = val.split()
				else:
					continue
				if parts:
					statuses.append(parts[0])
		return statuses

	@staticmethod
	def _extract_frnic_format(last_elem):
		"""
		Extract data from FRNIC format.

		Args:
			last_elem: The last element in the WHOIS chain

		Returns:
			dict: Extracted data
		"""
		domain_info = last_elem.get('domain', {})
		if not isinstance(domain_info, dict):
			domain_info = jswhois._find_frnic_domain_dict(last_elem) or {}

		nic_entries = jswhois._collect_nic_hdl_entries(last_elem)
		nic_index = jswhois._index_nic_hdl_entries(nic_entries)

		holder_handle = jswhois._first_str(domain_info.get('holder-c', ''))
		admin_handle = jswhois._first_str(domain_info.get('admin-c', ''))
		tech_handle = jswhois._first_str(domain_info.get('tech-c', ''))

		def pick_nic_entry(handle: str):
			if handle and handle in nic_index:
				return handle, nic_index[handle]
			# Fallback: best effort to select a representative entry
			if nic_entries:
				fallback = nic_entries[0]
				if isinstance(fallback, dict):
					fh = fallback.get('nic-hdl', '')
					return jswhois._first_str(fh), fallback
			return '', {}

		holder_h, holder_entry = pick_nic_entry(holder_handle)
		admin_h, admin_entry = pick_nic_entry(admin_handle)
		tech_h, tech_entry = pick_nic_entry(tech_handle)

		registrant_info = jswhois._frnic_contact_to_contact_info(holder_h, holder_entry)
		admin_info = jswhois._frnic_contact_to_contact_info(admin_h, admin_entry)
		tech_info = jswhois._frnic_contact_to_contact_info(tech_h, tech_entry)

		# Extract emails
		emails = []
		for cinfo in [registrant_info, admin_info, tech_info]:
			email = cinfo.get('email', '')
			if isinstance(email, str):
				email = email.strip()
				if email and email not in emails:
					emails.append(email)
		registrar_data = last_elem.get('registrar', {})
		if isinstance(registrar_data, dict):
			reg_email = registrar_data.get('e-mail', '')
			if isinstance(reg_email, str) and reg_email.strip() and reg_email.strip() not in emails:
				emails.append(reg_email.strip())

		# Extract registrant name/organization
		registrant = (
			registrant_info.get('organization')
			or registrant_info.get('name')
			or holder_handle
			or ''
			or jswhois._first_str(domain_info.get('holder-c', ''))
		)

		# Extract registrar info
		registrar_info = {}
		if isinstance(registrar_data, dict):
			registrar_info = {
				'registrar': registrar_data.get('registrar', ''),
				'e-mail': registrar_data.get('e-mail', ''),
				'phone': registrar_data.get('phone', ''),
				'fax': registrar_data.get('fax-no', ''),
				'website': registrar_data.get('website', ''),
				'address': registrar_data.get('address', []),
				'country': registrar_data.get('country', ''),
			}

		# Extract name servers
		name_servers = jswhois._extract_name_servers(
			last_elem.get('nserver', {})
		) or jswhois._extract_name_servers(domain_info)

		# Extract DNSSEC info
		dnssec_info = jswhois._extract_dnssec_info(last_elem, 'FRNIC')

		# Extract domain statuses for FRNIC
		domain_statuses = []
		status = domain_info.get('status', '')
		if status:
			domain_statuses.append(status)
		eppstatus = domain_info.get('eppstatus', '')
		if eppstatus:
			if isinstance(eppstatus, list):
				domain_statuses.extend(eppstatus)
			else:
				domain_statuses.append(eppstatus)

		return {
			'domain_name': domain_info.get('domain', ''),
			'registrar': domain_info.get('registrar', '') or registrar_data.get('registrar', ''),
			'creation_date': domain_info.get('created', ''),
			'expiration_date': domain_info.get('Expiry Date', ''),
			'last_update': domain_info.get('last-update', ''),
			'status': domain_info.get('status', ''),
			'eppstatus': domain_info.get('eppstatus', ''),
			'admin_c': domain_info.get('admin-c', ''),
			'tech_c': domain_info.get('tech-c', ''),
			'registrant': registrant,
			'emails': emails,
			'nic_hdl': holder_entry if isinstance(holder_entry, dict) else {},
			'nserver': last_elem.get('nserver', {}),
			'registrar_info': registrar_info,
			# New fields
			'registrant_info': registrant_info,
			'admin_info': admin_info,
			'tech_info': tech_info,
			'registry_ids': {},
			'dnssec_info': dnssec_info,
			'domain_statuses': domain_statuses,
			'name_servers': name_servers,
			'registrar_url': registrar_info.get('website', ''),
			'registrar_whois_server': '',
		}

	@staticmethod
	def _extract_generic_contact_ids(last_elem: Dict[str, Any], registry_ids: dict) -> Tuple[str, str]:
		"""
		Extract admin/tech contact IDs from registry IDs or nested sections.
		"""
		admin_c = registry_ids.get('registry_admin_id', '')
		tech_c = registry_ids.get('registry_tech_id', '')

		if not admin_c and isinstance(last_elem.get('Admin'), dict):
			admin_section = last_elem['Admin']
			admin_c = admin_section.get('ID', '') or admin_section.get('Handle', '')

		if not tech_c and isinstance(last_elem.get('Tech'), dict):
			tech_section = last_elem['Tech']
			tech_c = tech_section.get('ID', '') or tech_section.get('Handle', '')

		return admin_c, tech_c

	@staticmethod
	def _extract_generic_dates(last_elem: Dict[str, Any]) -> Tuple[Any, Any, Any]:
		"""
		Extract creation/expiration/update dates for generic WHOIS formats.

		This method prefers ICANN flat keys when present and falls back to a broader
		set of commonly used keys.
		"""
		icann_creation_date, icann_expiration_date, icann_last_update = jswhois._extract_icann_dates(last_elem)

		creation_patterns = ['Creation Date', 'Created', 'created', 'Creation', 'Registration Date']
		creation_date = icann_creation_date or jswhois._find_field_by_patterns(last_elem, creation_patterns, '')

		expiration_patterns = [
			'Expiry Date',
			'Expiration',
			'Expires',
			'Registrar Registration Expiration Date',
			'Registry Expiry Date',
		]
		expiration_date = icann_expiration_date or jswhois._find_field_by_patterns(last_elem, expiration_patterns, '')

		update_patterns = ['Updated Date', 'Last Updated', 'last-update', 'Last Update']
		last_update = icann_last_update or jswhois._find_field_by_patterns(last_elem, update_patterns, '')

		return creation_date, expiration_date, last_update

	@staticmethod
	def _extract_generic_emails(last_elem: Dict[str, Any]) -> List[str]:
		"""
		Extract unique, non-redacted emails from common generic WHOIS keys.
		"""
		emails: List[str] = []
		email_patterns = [
			'Admin Email',
			'Registrant Email',
			'Tech Email',
			'e-mail',
			'email',
			'Email',
			'Contact Email',
			'Registrar Abuse Contact Email',
		]
		for pattern in email_patterns:
			value = jswhois._find_field_by_patterns(last_elem, [pattern], '')
			jswhois._extend_unique_emails(emails, value)
		return emails

	@staticmethod
	def _extract_generic_format(last_elem: Dict[str, Any]) -> Dict[str, Any]:
		"""
		Extract data from generic/unknown format using pattern matching.

		Args:
			last_elem: The last element in the WHOIS chain

		Returns:
			dict: Extracted data
		"""
		domain_name = jswhois._find_field_by_patterns(
			last_elem,
			['Domain Name', 'domain', 'Domain', 'domain name'],
			'',
		)
		registrar = jswhois._find_field_by_patterns(
			last_elem,
			['Registrar', 'registrar', 'Registrar Name'],
			'',
		)
		creation_date, expiration_date, last_update = jswhois._extract_generic_dates(last_elem)

		domain_statuses = jswhois._extract_domain_statuses(last_elem)
		status, eppstatus = jswhois._format_domain_statuses(domain_statuses)

		emails = jswhois._extract_generic_emails(last_elem)
		registrant = jswhois._find_field_by_patterns(
			last_elem,
			['Registrant Organization', 'Registrant Name', 'Registrant', 'contact', 'Contact'],
			'',
		)

		registrant_info = jswhois._extract_contact_info(last_elem, 'Registrant')
		admin_info = jswhois._extract_contact_info(last_elem, 'Admin')
		tech_info = jswhois._extract_contact_info(last_elem, 'Tech')

		registry_ids = jswhois._extract_registry_ids(last_elem)
		dnssec_info = jswhois._extract_dnssec_info(last_elem, 'ICANN')

		name_servers = jswhois._extract_name_servers(last_elem)
		nserver = jswhois._build_nserver_dict(name_servers)

		registrar_info, registrar_url, registrar_whois_server = jswhois._extract_generic_registrar_metadata(
			last_elem,
			registrar,
		)
		admin_c, tech_c = jswhois._extract_generic_contact_ids(last_elem, registry_ids)

		return {
			'domain_name': domain_name,
			'registrar': registrar,
			'creation_date': creation_date,
			'expiration_date': expiration_date,
			'last_update': last_update,
			'status': status,
			'eppstatus': eppstatus,
			'admin_c': admin_c,
			'tech_c': tech_c,
			'registrant': registrant,
			'emails': emails,
			'nic_hdl': {},
			'nserver': nserver,
			'registrar_info': registrar_info,
			# New fields
			'registrant_info': registrant_info,
			'admin_info': admin_info,
			'tech_info': tech_info,
			'registry_ids': registry_ids,
			'dnssec_info': dnssec_info,
			'domain_statuses': domain_statuses,
			'name_servers': name_servers,
			'registrar_url': registrar_url,
			'registrar_whois_server': registrar_whois_server,
		}

	@staticmethod
	def _extract_generic_registrar_metadata(
		last_elem: Dict[str, Any],
		registrar: Any,
	) -> Tuple[Dict[str, Any], Any, Any]:
		"""
		Extract registrar-related metadata from generic WHOIS formats.
		"""
		registrar_info: Dict[str, Any] = {'registrar': registrar}

		abuse_email = jswhois._find_field_by_patterns(
			last_elem, ['Registrar Abuse Contact Email', 'Abuse Email'], ''
		)
		if abuse_email_str := jswhois._first_str(abuse_email):
			registrar_info['e-mail'] = abuse_email_str

		abuse_phone = jswhois._find_field_by_patterns(
			last_elem, ['Registrar Abuse Contact Phone', 'Abuse Phone'], ''
		)
		if abuse_phone_str := jswhois._first_str(abuse_phone):
			registrar_info['phone'] = abuse_phone_str

		registrar_url = jswhois._find_field_by_patterns(last_elem, ['Registrar URL'], '')
		registrar_whois_server = jswhois._find_field_by_patterns(last_elem, ['Registrar WHOIS Server'], '')

		return registrar_info, registrar_url, registrar_whois_server

	@staticmethod
	def _extract_iana_info(item: dict) -> dict:
		"""
		Extract IANA TLD information from the WHOIS chain.

		Args:
			item: Full jswhois JSON response

		Returns:
			dict: IANA TLD information
		"""
		iana_info = {
			'tld': '',
			'organisation': '',
			'contacts': [],
			'status': '',
			'remarks': '',
			'refer': '',
			'whois': '',
			'ds_rdata': '',
			'created': '',
			'changed': '',
		}

		chain = item.get('chain', [])
		if not chain or 'whois.iana.org' not in chain:
			return iana_info

		iana_data = item.get('whois.iana.org', {})
		if not isinstance(iana_data, dict):
			return iana_info

		# Extract TLD name
		iana_info['tld'] = iana_data.get('domain', '')

		# Extract refer/whois fields
		iana_info['refer'] = iana_data.get('refer', '') or iana_data.get('refer:', '') or iana_data.get('refer ', '')
		iana_info['whois'] = iana_data.get('whois', '')

		# Extract organisation
		org_data = iana_data.get('organisation', {})
		if isinstance(org_data, dict):
			iana_info['organisation'] = org_data.get('organisation', '')
		elif isinstance(org_data, str):
			iana_info['organisation'] = org_data

		# Extract contacts
		contacts = iana_data.get('contact', [])
		if isinstance(contacts, list):
			for contact in contacts:
				if isinstance(contact, dict):
					iana_info['contacts'].append({
						'type': contact.get('contact', ''),
						'name': contact.get('name', ''),
						'organisation': contact.get('organisation', ''),
						'email': contact.get('e-mail', ''),
						'phone': contact.get('phone', ''),
					})

		# Extract status
		status_data = iana_data.get('status', {})
		if isinstance(status_data, dict):
			iana_info['status'] = status_data.get('status', '')
			iana_info['remarks'] = status_data.get('remarks', '')
		elif isinstance(status_data, str):
			iana_info['status'] = status_data

		# Extract dates
		created_data = iana_data.get('created', {})
		if isinstance(created_data, dict):
			iana_info['created'] = created_data.get('created', '')
			iana_info['changed'] = created_data.get('changed', '')

		# Extract ds-rdata if present
		nserver_data = iana_data.get('nserver', {})
		if isinstance(nserver_data, dict):
			iana_info['ds_rdata'] = nserver_data.get('ds-rdata', '')

		return iana_info

	@staticmethod
	def _extract_icann_dates(data: dict) -> Tuple[str, str, str]:
		"""
		Extract common ICANN dates from a flat WHOIS mapping.
		"""
		if not isinstance(data, dict):
			return '', '', ''
		creation_date = data.get('Creation Date', '')
		expiration_date = (
			data.get('Registrar Registration Expiration Date', '') or
			data.get('Registry Expiry Date', '')
		)
		last_update = data.get('Updated Date', '')
		return creation_date, expiration_date, last_update

	@staticmethod
	def _extract_icann_flat_format(last_elem):
		"""
		Extract data from ICANN flat format (GANDI, GoDaddy, MarkMonitor, etc.).

		Args:
			last_elem: The last element in the WHOIS chain

		Returns:
			dict: Extracted data
		"""
		domain_name = last_elem.get('Domain Name', '')
		registrar = last_elem.get('Registrar', '')
		creation_date, expiration_date, last_update = jswhois._extract_icann_dates(last_elem)

		domain_statuses = jswhois._extract_domain_statuses(last_elem)
		status, eppstatus = jswhois._format_domain_statuses(domain_statuses)

		emails = jswhois._extract_unique_emails_from_fields(
			last_elem,
			[
				'Admin Email',
				'Registrant Email',
				'Tech Email',
				'Registrar Abuse Contact Email',
			],
		)

		registrant = last_elem.get('Registrant Organization', '') or last_elem.get('Registrant Name', '')

		# Extract contact information using new method
		registrant_info = jswhois._extract_contact_info(last_elem, 'Registrant')
		admin_info = jswhois._extract_contact_info(last_elem, 'Admin')
		tech_info = jswhois._extract_contact_info(last_elem, 'Tech')

		# Extract registry IDs
		registry_ids = jswhois._extract_registry_ids(last_elem)

		# Extract DNSSEC info
		dnssec_info = jswhois._extract_dnssec_info(last_elem, 'ICANN')

		# Extract name servers
		name_servers = jswhois._extract_name_servers(last_elem)
		nserver = {'nserver': name_servers} if name_servers else {}

		# Extract registrar info
		registrar_info = {
			'registrar': registrar,
			'e-mail': last_elem.get('Registrar Abuse Contact Email', ''),
			'phone': last_elem.get('Registrar Abuse Contact Phone', ''),
		}
		registrar_url = last_elem.get('Registrar URL', '')
		registrar_whois_server = last_elem.get('Registrar WHOIS Server', '')

		# Extract admin_c and tech_c from Registry IDs
		admin_c = registry_ids.get('registry_admin_id', '')
		tech_c = registry_ids.get('registry_tech_id', '')

		return {
			'domain_name': domain_name,
			'registrar': registrar,
			'creation_date': creation_date,
			'expiration_date': expiration_date,
			'last_update': last_update,
			'status': status,
			'eppstatus': eppstatus,
			'admin_c': admin_c,
			'tech_c': tech_c,
			'registrant': registrant,
			'emails': emails,
			'nic_hdl': {},
			'nserver': nserver,
			'registrar_info': registrar_info,
			# New fields
			'registrant_info': registrant_info,
			'admin_info': admin_info,
			'tech_info': tech_info,
			'registry_ids': registry_ids,
			'dnssec_info': dnssec_info,
			'domain_statuses': domain_statuses,
			'name_servers': name_servers,
			'registrar_url': registrar_url,
			'registrar_whois_server': registrar_whois_server,
		}

	@staticmethod
	def _extract_icann_nested_emails(last_elem: dict) -> List[str]:
		"""
		Extract emails from ICANN nested sections (Admin/Tech/Registrant) and
		from common flat contact fields.
		"""
		emails: List[str] = []

		for section_name in ('Admin', 'Tech', 'Registrant'):
			section = jswhois._get_nested_section(last_elem, section_name)
			jswhois._extend_unique_emails(
				emails,
				section.get('Email', '') or section.get('email', ''),
			)

		for email in jswhois._extract_unique_emails_from_fields(
			last_elem,
			['Admin Email', 'Registrant Email', 'Tech Email'],
		):
			if email not in emails:
				emails.append(email)

		return emails

	@staticmethod
	def _extract_icann_nested_format(last_elem: dict) -> dict:
		"""
		Extract data from ICANN nested format (with Admin, Tech, Registrant as dicts).

		Args:
			last_elem: The last element in the WHOIS chain

		Returns:
			dict: Extracted data
		"""
		extracted = jswhois._extract_icann_flat_format(last_elem)

		extracted['emails'] = jswhois._extract_icann_nested_emails(last_elem)
		extracted['registrant'] = jswhois._extract_icann_nested_registrant(last_elem)

		if not extracted.get('admin_c'):
			admin_section = jswhois._get_nested_section(last_elem, 'Admin')
			extracted['admin_c'] = admin_section.get('ID', '') or admin_section.get('Handle', '')

		if not extracted.get('tech_c'):
			tech_section = jswhois._get_nested_section(last_elem, 'Tech')
			extracted['tech_c'] = tech_section.get('ID', '') or tech_section.get('Handle', '')

		return extracted

	@staticmethod
	def _extract_icann_nested_registrant(last_elem: dict) -> str:
		"""
		Extract registrant name/organization from an ICANN nested format.
		"""
		registrant_section = jswhois._get_nested_section(last_elem, 'Registrant')
		registrant = (
			registrant_section.get('Organization', '') or
			registrant_section.get('Name', '')
		)
		if registrant:
			return registrant
		return last_elem.get('Registrant Organization', '') or last_elem.get('Registrant Name', '')

	@staticmethod
	def _extract_name_servers(data: dict) -> list:
		"""
		Extract name servers from WHOIS data.

		Args:
			data: Dictionary containing WHOIS data

		Returns:
			list: List of name server hostnames
		"""
		name_servers = []

		# Try different field names
		ns_value = data.get('Name Server', data.get('nserver', data.get('Name Servers', [])))

		if isinstance(ns_value, list):
			name_servers = [ns for ns in ns_value if ns]
		elif isinstance(ns_value, dict):
			# FRNIC format: nserver dict with 'nserver' key containing list
			inner_ns = ns_value.get('nserver', [])
			if isinstance(inner_ns, list):
				name_servers = inner_ns
			elif isinstance(inner_ns, dict):
				# IANA format: dict with NS names as keys
				name_servers = list(inner_ns.keys())
		elif ns_value:
			name_servers = [ns_value]

		return name_servers

	@staticmethod
	def _extract_registry_ids(data: dict) -> dict:
		"""
		Extract registry IDs from WHOIS data.

		Args:
			data: Dictionary containing WHOIS data

		Returns:
			dict: Registry IDs
		"""
		ids = {
			'registry_domain_id': '',
			'registry_registrant_id': '',
			'registry_admin_id': '',
			'registry_tech_id': '',
			'registrar_iana_id': '',
		}

		if not isinstance(data, dict):
			return ids

		id_mapping = {
			'registry_domain_id': ['Registry Domain ID', 'RegistryDomainID'],
			'registry_registrant_id': ['Registry Registrant ID', 'RegistryRegistrantID'],
			'registry_admin_id': ['Registry Admin ID', 'RegistryAdminID'],
			'registry_tech_id': ['Registry Tech ID', 'RegistryTechID'],
			'registrar_iana_id': ['Registrar IANA ID', 'RegistrarIANAID'],
		}

		for id_key, patterns in id_mapping.items():
			value = jswhois._find_field_by_patterns(data, patterns, '')
			value_str = jswhois._first_str(value)
			if value_str and value_str != 'REDACTED FOR PRIVACY' and value_str != 'Not Available From Registry':
				ids[id_key] = value_str

		return ids

	@staticmethod
	def _extract_unique_emails_from_fields(data: dict, field_names: List[str]) -> List[str]:
		"""
		Extract unique, non-redacted emails from a list of flat field names.
		"""
		emails: List[str] = []
		if not isinstance(data, dict):
			return emails
		for field in field_names:
			jswhois._extend_unique_emails(emails, data.get(field, ''))
		return emails

	@staticmethod
	def _find_field_by_patterns(data, patterns, default=''):
		"""
		Find a field in data by testing multiple pattern variations.

		Args:
			data: Dictionary or nested structure to search in
			patterns: List of field name patterns to try
			default: Default value if field not found

		Returns:
			Field value or default
		"""
		if not isinstance(data, dict):
			return default

		for pattern in patterns:
			# Try exact match (case-sensitive)
			if pattern in data:
				value = data[pattern]
				if value and value != '':
					return value

			# Try case-insensitive match
			for key in data.keys():
				if key.lower() == pattern.lower():
					value = data[key]
					if value and value != '':
						return value

		return default

	@staticmethod
	def _find_field_by_patterns_deep(data, patterns, default=''):
		"""
		Find a field in a nested structure by testing multiple pattern variations.

		This function first tries a shallow lookup on the provided dict, then falls back
		to a deep traversal to find matching keys anywhere in the structure.
		"""
		shallow = jswhois._find_field_by_patterns(data, patterns, default=None)
		if shallow not in (None, '', [], {}):
			return shallow

		if not patterns:
			return default

		patterns_lower = [p.lower() for p in patterns if isinstance(p, str)]
		for node in jswhois._walk(data):
			if not isinstance(node, dict):
				continue
			for key, value in node.items():
				if not isinstance(key, str):
					continue
				key_lower = key.lower()
				if (key in patterns or key_lower in patterns_lower) and (value and value != ''):
					return value

		return default

	@staticmethod
	def _find_frnic_domain_dict(data):
		"""
		Find a FRNIC-like 'domain' dict anywhere in the structure.
		"""
		for node in jswhois._walk(data):
			if not isinstance(node, dict):
				continue
			domain_info = node.get('domain')
			if isinstance(domain_info, dict) and any(
				key in domain_info for key in ['admin-c', 'tech-c', 'holder-c', 'eppstatus']
			):
				return domain_info
		return None

	@staticmethod
	def _first_str(value) -> str:
		"""
		Return the first non-empty string from a value that may be a string or a list.
		"""
		if isinstance(value, str):
			return value
		if isinstance(value, list):
			for v in value:
				if isinstance(v, str) and v.strip():
					return v
		return ''

	@staticmethod
	def _format_domain_statuses(domain_statuses: List[str]) -> Tuple[str, str]:
		"""
		Return the "status" and "eppstatus" fields from a domain status list.
		"""
		if not domain_statuses:
			return '', ''
		return domain_statuses[0], ', '.join(domain_statuses)

	@staticmethod
	def _frnic_contact_to_contact_info(handle: str, contact: dict) -> dict:
		"""
		Normalize a FRNIC nic-hdl dict into the standard contact structure used by jswhois.
		"""
		out = {
			'handle': handle or '',
			'name': '',
			'organization': '',
			'street': [],
			'city': '',
			'state_province': '',
			'postal_code': '',
			'country': '',
			'phone': '',
			'phone_ext': '',
			'fax': '',
			'fax_ext': '',
			'email': '',
		}
		if not isinstance(contact, dict):
			return out

		entity = contact.get('contact', '')
		if isinstance(entity, str) and entity.strip():
			out['name'] = entity.strip()
			out['organization'] = entity.strip()

		country = contact.get('country', '')
		if isinstance(country, str):
			out['country'] = country.strip()

		phone = contact.get('phone', '')
		if isinstance(phone, str):
			out['phone'] = phone.strip()

		email = contact.get('e-mail', '')
		if isinstance(email, str) and email.strip() and 'REDACTED' not in email.upper():
			out['email'] = email.strip()

		address = contact.get('address', [])
		lines = []
		if isinstance(address, list):
			lines = [a for a in address if isinstance(a, str) and a.strip()]
		elif isinstance(address, str) and address.strip():
			lines = [address.strip()]
		out['street'] = lines

		postal_code, city = jswhois._frnic_parse_postal_city(lines)
		out['postal_code'] = postal_code
		out['city'] = city

		return out

	@staticmethod
	def _frnic_parse_postal_city(address_lines: list) -> tuple:
		"""
		Best-effort parsing for FRNIC address lines.

		Returns (postal_code, city) parsed from the last line when it matches
		'<digits> <city>'.
		"""
		if not address_lines:
			return '', ''
		last = address_lines[-1]
		if not isinstance(last, str):
			return '', ''
		last = last.strip()
		if not last:
			return '', ''
		if parts := last.split():
			return (
				(parts[0], ' '.join(parts[1:]))
				if parts[0].isdigit() and len(parts) >= 2
				else ('', '')
			)
		else:
			return '', ''

	@staticmethod
	def _get_nested_section(last_elem: dict, section_name: str) -> dict:
		"""
		Return a nested ICANN section if present and valid.
		"""
		section = last_elem.get(section_name, {})
		return section if isinstance(section, dict) else {}

	@staticmethod
	def _index_nic_hdl_entries(entries: list) -> dict:
		"""
		Build an index handle -> nic-hdl entry dict.
		"""
		index = {}
		for entry in entries:
			if not isinstance(entry, dict):
				continue
			handle = entry.get('nic-hdl')
			if isinstance(handle, str) and handle.strip():
				index[handle.strip()] = entry
		return index

	@staticmethod
	def _iter_chain_servers(item: dict) -> Iterator[Tuple[str, dict]]:
		"""
		Yield (server, server_data) for each WHOIS server in the chain (excluding IANA).
		"""
		for server in item.get('chain', []):
			if server == 'whois.iana.org':
				continue
			server_data = item.get(server, {})
			if isinstance(server_data, dict):
				yield server, server_data

	@staticmethod
	def _iter_str_values(value) -> list:
		"""
		Normalize a value to a flat list of strings.

		This is required because jswhois data (especially raw-parsed) may contain
		repeated keys represented as lists.
		"""
		if value is None:
			return []
		if isinstance(value, str):
			return [value]
		if isinstance(value, list):
			out = []
			out.extend(v for v in value if isinstance(v, str))
			return out
		return []

	@staticmethod
	def _looks_like_email(value: str) -> bool:
		if not value or not isinstance(value, str):
			return False
		v = value.strip()
		return False if '@' not in v else not v.lower().startswith('http')

	@staticmethod
	def _looks_like_placeholder(value: str) -> bool:
		"""
		Detect values that should not be preferred when better data exists.
		"""
		if not value:
			return True
		if not isinstance(value, str):
			return False

		v = value.strip()
		if not v:
			return True

		upper = v.upper()
		if 'REDACTED FOR PRIVACY' in upper:
			return True
		if 'NOT AVAILABLE FROM REGISTRY' in upper:
			return True
		if upper.startswith('PLEASE QUERY THE RDDS SERVICE'):
			return True
		return bool(upper.startswith('SELECT REQUEST EMAIL FORM'))

	@staticmethod
	def _merge_candidates(candidates: list) -> tuple:
		"""
		Merge candidates field-by-field.

		Returns:
			merged_extracted, field_sources, sources_used
		"""
		field_sources: Dict[str, str] = {}

		domain_name = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'domain_name',
			lambda e: e.get('domain_name', ''),
		)
		registrar = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'registrar',
			lambda e: e.get('registrar', ''),
		)
		creation_date = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'creation_date',
			lambda e: e.get('creation_date', ''),
		)
		expiration_date = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'expiration_date',
			lambda e: e.get('expiration_date', ''),
		)
		last_update = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'last_update',
			lambda e: e.get('last_update', ''),
		)
		registrant = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'registrant',
			lambda e: e.get('registrant', ''),
		)

		domain_statuses = jswhois._merge_candidates_merge_list(
			candidates,
			field_sources,
			'domain_statuses',
			lambda e: e.get('domain_statuses', []),
		)
		name_servers = jswhois._merge_candidates_merge_list(
			candidates,
			field_sources,
			'name_servers',
			lambda e: e.get('name_servers', []),
			normalizer=lambda ns: ns.strip().lower().rstrip('.'),
		)

		# Registrar details
		registrar_url = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'registrar_url',
			lambda e: e.get('registrar_url', ''),
		)
		registrar_whois_server = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'registrar_whois_server',
			lambda e: e.get('registrar_whois_server', ''),
		)

		# Emails: keep all unique values, but avoid preferring placeholders for contact.email
		emails = jswhois._merge_candidates_merge_list(
			candidates,
			field_sources,
			'emails',
			lambda e: e.get('emails', []),
		)

		# Contacts
		registrant_info = jswhois._merge_candidates_merge_contact(candidates, field_sources, 'registrant_info')
		admin_info = jswhois._merge_candidates_merge_contact(candidates, field_sources, 'admin_info')
		tech_info = jswhois._merge_candidates_merge_contact(candidates, field_sources, 'tech_info')

		merged: Dict[str, Any] = {
			'domain_name': domain_name,
			'registrar': registrar,
			'creation_date': creation_date,
			'expiration_date': expiration_date,
			'last_update': last_update,
			'registrant': registrant,
			'domain_statuses': domain_statuses,
			'name_servers': name_servers,
			'registrar_url': registrar_url,
			'registrar_whois_server': registrar_whois_server,
			'emails': emails,
			'registrant_info': registrant_info,
			'admin_info': admin_info,
			'tech_info': tech_info,
		}

		# Contact extras (Application Purpose, Nexus Category)
		merged['contacts_extra'] = {
			'registrant': {},
			'admin': {},
			'tech': {},
		}
		for k in ['application_purpose', 'nexus_category']:
			merged['contacts_extra']['registrant'][k] = jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				f'contacts_extra.registrant.{k}',
				lambda e, kk=k: (e.get('contacts_extra', {}) or {}).get('registrant', {}).get(kk, ''),
			)
			merged['contacts_extra']['admin'][k] = jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				f'contacts_extra.admin.{k}',
				lambda e, kk=k: (e.get('contacts_extra', {}) or {}).get('admin', {}).get(kk, ''),
			)
			merged['contacts_extra']['tech'][k] = jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				f'contacts_extra.tech.{k}',
				lambda e, kk=k: (e.get('contacts_extra', {}) or {}).get('tech', {}).get(kk, ''),
			)

		# Registry IDs
		merged['registry_ids'] = {}
		for k in [
			'registry_domain_id',
			'registry_registrant_id',
			'registry_admin_id',
			'registry_tech_id',
			'registrar_iana_id',
		]:
			merged['registry_ids'][k] = jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				f'registry_ids.{k}',
				lambda e, kk=k: (e.get('registry_ids', {}) or {}).get(kk, ''),
			)

		# Registrar info dict
		merged['registrar_info'] = {}
		registrar_info_keys = set()
		for c in candidates:
			info = c['extracted'].get('registrar_info', {})
			if isinstance(info, dict):
				registrar_info_keys.update(info.keys())
		for k in sorted(registrar_info_keys):
			merged['registrar_info'][k] = jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				f'registrar_info.{k}',
				lambda e, kk=k: (e.get('registrar_info', {}) or {}).get(kk, ''),
			)

		# FRNIC nic-hdl best effort (pick most complete dict)
		best_nic_hdl = {}
		best_nic_server = ''
		best_len = -1
		for c in candidates:
			nh = c['extracted'].get('nic_hdl', {})
			if isinstance(nh, dict):
				non_empty = sum(v not in (None, '', [], {}) for v in nh.values())
				score = non_empty + jswhois._candidate_weight(c)
				if score > best_len:
					best_len = score
					best_nic_hdl = nh
					best_nic_server = c['server']
		merged['nic_hdl'] = best_nic_hdl
		if best_nic_server:
			field_sources['nic_hdl'] = best_nic_server

		# nserver best effort (keep richer dicts if present)
		best_nserver = {}
		best_ns_server = ''
		best_ns_len = -1
		for c in candidates:
			ns = c['extracted'].get('nserver', {})
			if isinstance(ns, dict):
				non_empty = sum(v not in (None, '', [], {}) for v in ns.values())
				score = non_empty + jswhois._candidate_weight(c)
				if score > best_ns_len:
					best_ns_len = score
					best_nserver = ns
					best_ns_server = c['server']
		merged['nserver'] = best_nserver
		if best_ns_server:
			field_sources['nserver'] = best_ns_server

		# DNSSEC
		dnssec = jswhois._merge_candidates_pick_scalar(
			candidates,
			field_sources,
			'dnssec',
			lambda e: (e.get('dnssec_info', {}) or {}).get('dnssec', ''),
		)
		keys = []
		for c in candidates:
			klist = (c['extracted'].get('dnssec_info', {}) or {}).get('dnssec_keys', [])
			if isinstance(klist, list):
				keys.extend(klist)
		merged['dnssec_info'] = {'dnssec': dnssec, 'dnssec_keys': keys}

		# Status/eppstatus fallback from statuses list
		merged['status'] = (
			merged['domain_statuses'][0]
			if merged['domain_statuses']
			else jswhois._merge_candidates_pick_scalar(candidates, field_sources, 'status', lambda e: e.get('status', ''))
		)
		merged['eppstatus'] = (
			', '.join(merged['domain_statuses'])
			if merged['domain_statuses']
			else jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				'eppstatus',
				lambda e: e.get('eppstatus', ''),
			)
		)

		# Determine sources used
		sources_used = sorted(set(field_sources.values()) - {'multiple'})

		# Select a primary server (most fields contributed)
		counts = {}
		for server in field_sources.values():
			if server not in ('multiple', ''):
				counts[server] = counts.get(server, 0) + 1
		primary_server = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[0][0] if counts else ''

		return merged, field_sources, sources_used, primary_server

	@staticmethod
	def _merge_candidates_merge_contact(candidates: list, field_sources: dict, prefix: str) -> dict:
		"""
		Merge a contact dict (registrant/admin/tech) field-by-field.
		"""
		contact = {
			'handle': '',
			'name': '',
			'organization': '',
			'street': [],
			'city': '',
			'state_province': '',
			'postal_code': '',
			'country': '',
			'phone': '',
			'phone_ext': '',
			'fax': '',
			'fax_ext': '',
			'email': '',
		}
		for k in [
			'handle',
			'name',
			'organization',
			'city',
			'state_province',
			'postal_code',
			'country',
			'phone',
			'phone_ext',
			'fax',
			'fax_ext',
		]:
			contact[k] = jswhois._merge_candidates_pick_scalar(
				candidates,
				field_sources,
				f'{prefix}.{k}',
				lambda e, kk=k: (e.get(prefix, {}) or {}).get(kk, ''),
			)

		# Email: prefer real email address over placeholders/URLs.
		contact['email'] = jswhois._merge_candidates_pick_email(
			candidates,
			field_sources,
			f'{prefix}.email',
			lambda e: (e.get(prefix, {}) or {}).get('email', ''),
		)

		# Street: union.
		contact['street'] = jswhois._merge_candidates_merge_list(
			candidates,
			field_sources,
			f'{prefix}.street',
			lambda e: (e.get(prefix, {}) or {}).get('street', []),
		)
		return contact

	@staticmethod
	def _merge_candidates_merge_list(
		candidates: list,
		field_sources: dict,
		key_path: str,
		getter,
		normalizer=None,
	) -> list:
		merged: List[str] = []
		seen = set()
		for c in sorted(candidates, key=jswhois._candidate_weight, reverse=True):
			vals = getter(c['extracted'])
			if not vals:
				continue
			if not isinstance(vals, list):
				vals = [vals]
			for v in vals:
				if not isinstance(v, str):
					continue
				v = v.strip()
				if not v:
					continue
				n = normalizer(v) if normalizer else v
				if n in seen:
					continue
				seen.add(n)
				merged.append(v)
		if merged:
			field_sources[key_path] = 'multiple'
		return merged

	@staticmethod
	def _merge_candidates_pick_email(candidates: list, field_sources: dict, key_path: str, getter) -> str:
		best = ''
		best_score = -1
		best_server = ''
		for c in candidates:
			val = getter(c['extracted'])
			if not isinstance(val, str):
				continue
			val = val.strip()
			if not val:
				continue
			score = 0
			if jswhois._looks_like_placeholder(val):
				score -= 50
			if jswhois._looks_like_email(val):
				score += 100
			elif val.lower().startswith('http'):
				score -= 10
			score += jswhois._candidate_weight(c)
			if score > best_score:
				best = val
				best_score = score
				best_server = c['server']
		if best_server:
			field_sources[key_path] = best_server
		return best

	@staticmethod
	def _merge_candidates_pick_scalar(candidates: list, field_sources: dict, key_path: str, getter) -> str:
		best = ''
		best_score = -1
		best_server = ''
		for c in candidates:
			val = getter(c['extracted'])
			if not isinstance(val, str):
				continue
			val = val.strip()
			if not val:
				continue
			score = 0 if jswhois._looks_like_placeholder(val) else 100
			score += jswhois._candidate_weight(c)
			if score > best_score:
				best = val
				best_score = score
				best_server = c['server']
		if best_server:
			field_sources[key_path] = best_server
		return best

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
	def _raw_to_kv(raw: str) -> dict:
		"""
		Parse WHOIS raw output into a key-value dictionary.

		- Supports repeated keys by turning values into lists.
		- Splits on the first ':' only.
		- Ignores disclaimer/empty lines.

		Args:
			raw: Raw WHOIS text

		Returns:
			Parsed dict
		"""
		if not raw or not isinstance(raw, str):
			return {}

		out: dict = {}
		for line in raw.splitlines():
			line = line.strip()
			if not line:
				continue
			if line.startswith('%') or line.startswith('>>>') or line.startswith('**'):
				continue
			if ':' not in line:
				continue

			key, value = line.split(':', 1)
			key = key.strip()
			value = value.strip()
			if not key:
				continue

			# Normalize repeated "Domain Status:" lines that may include URL in same line
			existing = out.get(key)
			if existing is None:
				out[key] = value
			elif isinstance(existing, list):
				existing.append(value)
			else:
				out[key] = [existing, value]

		return out

	@staticmethod
	def _sanitize_email(value: object) -> str:
		"""
		Return a normalized email address or an empty string if invalid/unusable.
		"""
		return (
			email
			if isinstance(value, str)
			and (email := value.strip())
			and 'REDACTED' not in email.upper()
			else ''
		)

	@staticmethod
	def _strip_raw_fields(obj: Any) -> Any:
		"""
		Recursively remove keys named \"raw\" from a nested dict/list structure.
		"""
		if isinstance(obj, dict):
			return {k: jswhois._strip_raw_fields(v) for k, v in obj.items() if k != 'raw'}
		if isinstance(obj, list):
			return [jswhois._strip_raw_fields(inner_item) for inner_item in obj]
		return obj

	@staticmethod
	def _walk(obj):
		"""
		Iterate over nested dict/list nodes (depth-first) to support generic extraction.
		"""
		stack = [obj]
		while stack:
			current = stack.pop()
			yield current
			if isinstance(current, dict):
				stack.extend(v for v in current.values() if isinstance(v, (dict, list)))
			elif isinstance(current, list):
				stack.extend(v for v in current if isinstance(v, (dict, list)))
