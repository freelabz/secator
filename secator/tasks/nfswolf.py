import json
import os
import shlex

from secator.decorators import task
from secator.definitions import IP, HOST, HOST_PORT, CIDR_RANGE, TIMEOUT, PROXY, THREADS, OPT_NOT_SUPPORTED, HEADER, FOLLOW_REDIRECT, USER_AGENT, DELAY, RETRIES, RATE_LIMIT
from secator.output_types import Port, Ip, Tag, Vulnerability, Info, Error, Technology
from secator.tasks._categories import Vuln
from secator.utils import autodetect_type


@task()
class nfswolf(Vuln):
	"""NFSWolf is a complete NFS vulnerability scanner."""
	cmd = 'nfswolf scan'
	input_chunk_size = 1
	input_types = [IP, HOST, HOST_PORT, CIDR_RANGE]
	output_types = [Port, Ip, Tag, Vulnerability]
	opt_prefix = '--'
	input_flag = None
	file_flag = None
	json_flag = '--json'
	opts = {
		'output_path': {'type': str, 'default': None, 'help': 'Output JSON file path', 'internal': True, 'display': False},
		'nfs_port': {'type': int, 'default': 2049, 'help': 'NFS port (skip portmapper)'},
		'mount_port': {'type': int, 'default': None, 'help': 'Mount port (skip portmapper)'},
		'rpc_port': {'type': int, 'default': None, 'help': 'RPC port (overrides portmapper / rpcbind port)'},
		'scan_udp': {'is_flag': True, 'default': False, 'help': 'Probe all ports over UDP in addition to TCP'}
	}
	opt_key_map = {
		THREADS: 'concurrency',
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'delay',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED
	}
	opt_value_map = {
		TIMEOUT: lambda x: int(x * 1000),
		DELAY: lambda x: int(x * 1000),
	}
	proxychains = False
	proxy_socks5 = True
	proxy_http = False
	github_handle = 'freelabz/NFSWolf'
	install_binary_name = 'nfswolf'
	install_version = 'v1.2.0'
	install_cmd = 'cargo install --git https://github.com/freelabz/NFSWolf --tag [install_version] nfswolf'
	profile = 'small'

	@staticmethod
	def on_cmd(self):
		default_output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = self.get_opt_value('output_path') or default_output_path
		self.cmd = self.cmd.replace('--json', f'--json {shlex.quote(self.output_path)}')

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
			host, port = tuple(self.inputs[0].split(':'))
			self.cmd = self.cmd.replace(self.inputs[0], host)
			self.inputs[0] = host
			opts['nfs_port']['value'] = int(port)
		return opts

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return
		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			content = json.load(f)
		full_target = self.inputs[0] + ':' + str(self.get_opt_value('nfs_port'))
		hosts = content.get('hosts', [])
		for host in hosts:
			ip = host['ip']
			hostname = host['hostname'] or ip

			# OS Guess
			os_guess = host['os_guess']
			if os_guess:
				yield Tag(
					match=hostname,
					category='info',
					name='OS Guess',
					value=os_guess
				)

			# Portmap
			portmap = host['portmap']
			for protocol, enabled in portmap.items():
				if enabled:
					yield Tag(
						match=hostname,
						category='info',
						name=protocol.upper(),
						value='enabled'
					)

			# RPC services
			rpc_services = host['rpc_services']
			techs_grouped = {}
			for service in rpc_services:
				port = service['port']
				version = service['version']
				program_name = service['program_name']
				program_id = service['program']
				if program_name == 'nfs':
					program_full = f'{program_name}:{version}'
				else:
					program_full = f'{program_name}'
				if program_full in techs_grouped:
					techs_grouped[program_full]['protocols'].append(service['protocol'])
				else:
					techs_grouped[program_full] = {}
					techs_grouped[program_full]['protocols'] = [service['protocol']]
					techs_grouped[program_full]['version'] = version if program_name == 'nfs' else None
					techs_grouped[program_full]['match'] = f'{hostname}:{port}'
					techs_grouped[program_full]['program_name'] = program_name
					techs_grouped[program_full]['program_id'] = program_id
				security_note = service['security_note']
				if security_note:
					entity = program_name.replace('_', ' ').capitalize() + f'v{version}'
					confidence = 'low' if 'may' in security_note else 'high'
					tags = ['network', 'nfs']
					if confidence == 'high':
						tags.append('vuln')
					yield Vulnerability(
						matched_at=f'{hostname}:{port}',
						ip=ip,
						name='NFS - ' + security_note.capitalize(),
						severity='low',
						confidence=confidence,
						extra_data={
							'program_name': program_name,
							'version': version
						},
						tags=tags
					)

			# Technologies
			for data in techs_grouped.values():
				mapped_names = {
					'portmapper': 'rpcbind',
					'statd': 'rpc.statd',
					'mountd': 'rpc.mountd'
				}
				program_name = data['program_name']
				if data['program_name'] in mapped_names:
					program_name = mapped_names[program_name]
				yield Technology(
					match=data['match'],
					product=program_name,
					version=data['version'],
					extra_data={
						'protocols': ','.join(set(data['protocols'])),
						'program_id': data['program_id'],
					}
				)

			# Exports
			exports = host['exports']
			for version, data in exports.items():
				if not data:
					continue
				for item in data:
					allowed = item.get('allowed')
					if allowed:
						allowed = ";".join(allowed)
					yield Vulnerability(
						matched_at=full_target,
						ip=ip,
						name='NFS - Unauthenticated Access',
						description=(
							'An NFS share has an export with a path or file that can '
							'be accessed without authentication.'
						),
						impact=(
							'Unauthenticated NFS access can lead to leaking sensitive data '
							'or credentails remote clients, which can lead to further exploitation.'
						),
						remediation=(
							'Disable NFS share exports or require authentication to access them.'
						),
						severity='high',
						confidence='high',
						extra_data={
							'path': item['path'],
							'handle': item.get('handle'),
							'allowed': allowed,
							'version': version
						},
						tags=['network', 'nfs', 'unauth', 'vuln'],
					)
