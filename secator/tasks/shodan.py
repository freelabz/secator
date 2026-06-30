import contextlib
import ipaddress
import os
import socket
import unittest.mock

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HOST, IP
from secator.output_types import (
	Error, Ip, Port, Record, Subdomain, Tag, Technology, Vulnerability, Warning
)
from secator.runners import PythonRunner


@task()
class shodan(PythonRunner):
	"""Passive host recon via the Shodan API (ports, services, CVEs, hostnames)."""
	input_types = [HOST, IP]
	output_types = [Ip, Subdomain, Port, Technology, Vulnerability, Tag, Record]
	tags = ['shodan', 'recon', 'osint', 'passive']
	install_cmd = 'pip install shodan'
	opts = {
		'operation': {'type': str, 'default': 'host', 'short': 'op', 'help': 'Operation: host | dns | search'},
		# Empty default + runtime fallback (never a CONFIG default — it would leak
		# the configured key into the secator-api UI form, like the `ai` task).
		'api_key': {'type': str, 'default': '', 'help': 'Shodan API key (defaults to configured key)'},
		'history': {'is_flag': True, 'default': False, 'help': 'Include historical (non-current) banners'},
		'minify': {'is_flag': True, 'default': False, 'help': 'Only ports + general host info (no banners)'},
		'resolver': {'type': str, 'default': 'local', 'help': 'host mode: hostname resolver — local | shodan'},
		'record_types': {'type': list, 'default': ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'],
						 'help': 'dns mode: DNS record types to emit'},
		'limit': {'type': int, 'default': 100, 'help': 'search mode: max results (one page = 100)'},
	}

	def yielder(self):
		try:
			import shodan as shodan_sdk
		except ImportError:
			yield Error(message="The 'shodan' package is not installed. Run: pip install shodan")
			return

		api_key = (
			self.get_opt_value('api_key')
			or CONFIG.addons.shodan.api_key
			or os.environ.get('SHODAN_API_KEY', '')
		)
		if not api_key:
			yield Error(message='Shodan API key not configured (set the api_key opt, '
								'CONFIG.addons.shodan.api_key, or the SHODAN_API_KEY env var).')
			return

		api = shodan_sdk.Shodan(api_key)
		operation = self.get_opt_value('operation') or 'host'
		if operation == 'host':
			yield from self._run_host(api, shodan_sdk)
		elif operation == 'dns':
			yield from self._run_dns(api, shodan_sdk)
		elif operation == 'search':
			yield from self._run_search(api, shodan_sdk)
		else:
			yield Error(message=f"Unknown Shodan operation '{operation}' (expected host | dns | search).")

	def _run_host(self, api, shodan_sdk):
		history = self.get_opt_value('history')
		minify = self.get_opt_value('minify')
		for target in self.inputs:
			ip, hostname = target, ''
			if not self._is_ip(target):
				hostname = target
				if (self.get_opt_value('resolver') or 'local') == 'shodan':
					try:
						ip = self._shodan_resolve(api, target)
					except shodan_sdk.APIError as e:
						yield Error(message=f'Shodan DNS resolve failed for {target}: {e}')
						continue
					if not ip:
						yield Error(message=f'Shodan DNS has no A record for {target}')
						continue
				else:
					try:
						ip = socket.gethostbyname(target)
					except (socket.gaierror, OSError) as e:
						yield Error(message=f'Could not resolve {target}: {e}')
						continue
			try:
				data = api.host(ip, history=history, minify=minify)
			except shodan_sdk.APIError as e:
				msg = str(e)
				if 'No information available' in msg:
					yield Warning(message=f'No Shodan data for {ip}')
				else:
					yield Error(message=f'Shodan API error for {ip}: {msg}')
				continue
			host = hostname or (data.get('hostnames') or [''])[0]
			yield from self._map_host(data, ip, host)

	def _run_dns(self, api, shodan_sdk):
		record_types = [str(t).upper() for t in (self.get_opt_value('record_types') or [])]
		for domain in self.inputs:
			try:
				info = api.dns.domain_info(domain)
			except shodan_sdk.APIError as e:
				msg = str(e)
				if 'No information' in msg or 'Invalid' in msg:
					yield Warning(message=f'No Shodan DNS data for {domain}')
				else:
					yield Error(message=f'Shodan DNS error for {domain}: {msg}')
				continue
			yield from self._map_dns(domain, info, record_types)

	def _map_dns(self, domain, info, record_types):
		for r in (info.get('data') or []):
			rtype = str(r.get('type') or '').upper()
			if record_types and rtype not in record_types:
				continue
			sub = r.get('subdomain') or ''
			fqdn = f'{sub}.{domain}' if sub else domain
			value = r.get('value')
			yield Record(
				name=fqdn, type=rtype, host=domain,
				extra_data=self._compact({'value': value, 'last_seen': r.get('last_seen'), 'ports': r.get('ports')}),
				tags=['shodan'],
			)
			if rtype in ('A', 'AAAA') and value and self._is_public_ip(value):
				yield Ip(ip=value, host=fqdn, alive=True, tags=['shodan'])
		seen = set()
		for sub in (info.get('subdomains') or []):
			host = f'{sub}.{domain}'
			if host not in seen:
				seen.add(host)
				yield Subdomain(host=host, domain=domain, sources=['shodan'])

	def _shodan_resolve(self, api, host):
		"""Resolve a hostname to an IP via Shodan DNS (no local resolver). Returns the
		first matching A-record value, or None."""
		domain = self._registered_domain(host)
		sub = host[:-len(domain)].rstrip('.') if host != domain else ''
		info = api.dns.domain_info(domain)
		for r in (info.get('data') or []):
			if str(r.get('type')) == 'A' and (r.get('subdomain') or '') == sub:
				return r.get('value')
		return None

	def _run_search(self, api, shodan_sdk):
		query = ' '.join(self.inputs).strip()
		if not query:
			yield Error(message='Shodan search requires a query (pass it as the input).')
			return
		limit = self.get_opt_value('limit') or 100
		try:
			result = api.search(query, limit=limit)
		except shodan_sdk.APIError as e:
			yield Error(message=f'Shodan search error: {e}')
			return
		yield Tag(name='shodan_search_total', value=str(result.get('total', 0)),
				  match=query, category='info', tags=['shodan'])
		for match in (result.get('matches') or []):
			ip_str = match.get('ip_str')
			if not ip_str:
				continue
			host = (match.get('hostnames') or [''])[0]
			yield Ip(
				ip=ip_str, host=host, alive=True,
				extra_data=self._compact({'os': match.get('os'), 'org': match.get('org'),
										  'isp': match.get('isp'), 'asn': match.get('asn')}),
				tags=['shodan'],
			)
			seen = set()
			for name in (match.get('hostnames') or []):
				if name and name not in seen:
					seen.add(name)
					yield Subdomain(host=name, domain=self._registered_domain(name), sources=['shodan'])
			yield from self._map_banner(match, ip_str, host)

	def _map_host(self, h, ip, host):
		ip_str = h.get('ip_str', ip)
		yield Ip(
			ip=ip_str, host=host, alive=True,
			extra_data=self._compact({
				'os': h.get('os'), 'org': h.get('org'), 'isp': h.get('isp'),
				'asn': h.get('asn'), 'country': h.get('country_name'),
			}),
			tags=['shodan'],
		)
		seen = set()
		for name in (h.get('hostnames') or []) + (h.get('domains') or []):
			if name and name not in seen:
				seen.add(name)
				yield Subdomain(host=name, domain=self._registered_domain(name), sources=['shodan'])
		for key, label in (('org', 'shodan_org'), ('isp', 'shodan_isp'),
						   ('asn', 'shodan_asn'), ('os', 'shodan_os')):
			val = h.get(key)
			if val:
				yield Tag(name=label, value=str(val), match=ip_str, category='info', tags=['shodan'])
		for cve in (h.get('vulns') or []):
			yield Vulnerability(name=cve, id=cve, matched_at=ip_str, ip=ip_str,
								provider='shodan', confidence='low', tags=['shodan'])
		for b in (h.get('data') or []):
			yield from self._map_banner(b, ip_str, host)

	def _map_banner(self, b, ip_str, host):
		port = b.get('port')
		try:
			port = int(port)
		except (TypeError, ValueError):
			return
		yield Port(
			port=port, ip=ip_str, host=host, state='open',
			protocol=b.get('transport', 'tcp'),
			service_name=b.get('product', '') or '',
			cpes=b.get('cpe', []) or [],
			confidence='low', service_confidence='low',
			extra_data=self._compact({'version': b.get('version'), 'banner': self._excerpt(b.get('data'))}),
			tags=['shodan'],
		)
		product = b.get('product')
		if product:
			yield Technology(
				product=product, match=f'{ip_str}:{port}', version=b.get('version'),
				extra_data=self._compact({'cpe': b.get('cpe')}), tags=['shodan'],
			)
		for cve, meta in (b.get('vulns') or {}).items():
			cvss = 0.0
			if isinstance(meta, dict) and meta.get('cvss') is not None:
				try:
					cvss = float(meta.get('cvss'))
				except (TypeError, ValueError):
					cvss = 0.0
			yield Vulnerability(
				name=cve, id=cve, matched_at=f'{ip_str}:{port}', ip=ip_str,
				provider='shodan', confidence='low', cvss_score=cvss,
				description=(meta.get('summary', '') if isinstance(meta, dict) else ''),
				tags=['shodan'],
			)

	@staticmethod
	def _is_ip(value):
		try:
			ipaddress.ip_address(value)
			return True
		except ValueError:
			return False

	@staticmethod
	def _is_public_ip(value):
		try:
			return ipaddress.ip_address(value).is_global
		except ValueError:
			return False

	@staticmethod
	def _registered_domain(hostname):
		parts = hostname.split('.')
		return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

	@staticmethod
	def _excerpt(text, length=500):
		return (text or '')[:length]

	@staticmethod
	def _compact(d):
		return {k: v for k, v in d.items() if v not in (None, '', [], {})}

	@classmethod
	def get_mock_context(cls, fixture):
		"""Mock the Shodan SDK + DNS for the PythonRunner unit-test harness (no network)."""
		@contextlib.contextmanager
		def _ctx():
			mock_api = unittest.mock.MagicMock()
			mock_api.host.return_value = fixture
			patch_shodan = unittest.mock.patch('shodan.Shodan', return_value=mock_api)
			patch_dns = unittest.mock.patch('socket.gethostbyname', return_value='10.0.0.1')
			with patch_shodan, patch_dns:
				yield
		return _ctx()

	@staticmethod
	def validate_input(self, inputs):
		# In search mode the input is a free-text Shodan query (e.g. "apache country:US"),
		# not a HOST/IP — accept it. host/dns inputs are still typed via input_types.
		return True
