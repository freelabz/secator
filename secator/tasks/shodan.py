import contextlib
import ipaddress
import os
import socket
import unittest.mock

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HOST, IP
from secator.output_types import (
	Error, Ip, Port, Subdomain, Tag, Technology, Vulnerability, Warning
)
from secator.runners import PythonRunner


@task()
class shodan(PythonRunner):
	"""Passive host recon via the Shodan API (ports, services, CVEs, hostnames)."""
	input_types = [HOST, IP]
	output_types = [Ip, Subdomain, Port, Technology, Vulnerability, Tag]
	tags = ['shodan', 'recon', 'osint', 'passive']
	install_cmd = 'pip install shodan'
	opts = {
		# Empty default + runtime fallback (never a CONFIG default — it would leak
		# the configured key into the secator-api UI form, like the `ai` task).
		'api_key': {'type': str, 'default': '', 'help': 'Shodan API key (defaults to configured key)'},
		'history': {'is_flag': True, 'default': False, 'help': 'Include historical (non-current) banners'},
		'minify': {'is_flag': True, 'default': False, 'help': 'Only ports + general host info (no banners)'},
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
		history = self.get_opt_value('history')
		minify = self.get_opt_value('minify')

		for target in self.inputs:
			ip, hostname = target, ''
			if not self._is_ip(target):
				hostname = target
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
			port = b.get('port')
			try:
				port = int(port)
			except (TypeError, ValueError):
				continue
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
