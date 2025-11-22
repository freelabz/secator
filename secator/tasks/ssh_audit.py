import json
import os

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Vulnerability, Error, Info, Tag
from secator.definitions import HOST, IP, OUTPUT_PATH, TIMEOUT
from secator.tasks._categories import Command


@task()
class ssh_audit(Command):
	"""SSH server & client security auditing (banner, key exchange, encryption, mac, compression, etc)."""
	cmd = 'ssh-audit'
	input_types = [HOST, IP]
	output_types = [Vulnerability, Tag]
	tags = ['ssh', 'audit', 'security']
	input_flag = None
	file_flag = '-T'
	opt_prefix = '--'
	opts = {
		'port': {'type': int, 'short': 'p', 'default': 22, 'help': 'Port to connect to'},
		'ipv4': {'is_flag': True, 'short': '4', 'default': False, 'help': 'Enable IPv4 (order of precedence)'},
		'ipv6': {'is_flag': True, 'short': '6', 'default': False, 'help': 'Enable IPv6 (order of precedence)'},
		'batch': {'is_flag': True, 'short': 'b', 'default': False,
			'help': 'Enable batch output for automated processing'},
		'client_audit': {'is_flag': True, 'short': 'c', 'default': False,
			'help': 'Start a listening server for client auditing'},
		'level': {'type': str, 'short': 'l', 'default': None, 'help': 'Minimum output level (info, warn, fail)'},
		'verbose': {'is_flag': True, 'short': 'v', 'default': False, 'help': 'Enable verbose output'},
	}
	opt_key_map = {
		TIMEOUT: 'timeout',
		'port': '-p',
		'ipv4': '-4',
		'ipv6': '-6',
		'batch': '-b',
		'client_audit': '-c',
		'level': '-l',
		'verbose': '-v',
	}
	install_github_handle = 'jtesta/ssh-audit'
	install_version = 'v3.3.0'
	install_cmd = (
		f'git clone --depth 1 --single-branch -b [install_version] '
		f'https://github.com/jtesta/ssh-audit.git {CONFIG.dirs.share}/ssh-audit_[install_version] || true && '
		f'ln -sf {CONFIG.dirs.share}/ssh-audit_[install_version]/ssh-audit.py {CONFIG.dirs.bin}/ssh-audit && '
		f'chmod +x {CONFIG.dirs.bin}/ssh-audit'
	)
	profile = 'io'
	ignore_return_code = True

	@staticmethod
	def on_cmd(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd += f' -jj --json={self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return
		yield Info(message=f'JSON results saved to {self.output_path}')

		verbose = self.get_opt_value('verbose')

		with open(self.output_path, 'r') as f:
			data = json.load(f)

			target = data.get('target', 'unknown')
			banner = data.get('banner', {})
			software = banner.get('software', 'unknown')

			# Process CVEs
			cves = data.get('cves', [])
			for cve in cves:
				yield Vulnerability(
					name=f'SSH {cve}',
					matched_at=target,
					tags=['ssh', 'cve'],
					severity='high',
					confidence='high',
					provider='ssh_audit',
					extra_data={
						'cve': cve,
						'software': software
					}
				)

			# Process encryption algorithms
			enc_list = data.get('enc', [])
			for enc in enc_list:
				algorithm = enc.get('algorithm', '')
				notes = enc.get('notes', {})
				failures = notes.get('fail', [])
				warnings = notes.get('warn', [])

				# Create vulnerabilities for failures
				for failure in failures:
					yield Vulnerability(
						name=f'SSH weak encryption algorithm: {algorithm}',
						matched_at=target,
						tags=['ssh', 'encryption', 'cipher'],
						severity='high',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': failure,
							'type': 'encryption'
						}
					)

				# Create vulnerabilities for warnings
				for warning in warnings:
					yield Vulnerability(
						name=f'SSH encryption algorithm warning: {algorithm}',
						matched_at=target,
						tags=['ssh', 'encryption', 'cipher'],
						severity='medium',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': warning,
							'type': 'encryption'
						}
					)

				# Create info tags for successful algorithms if verbose
				if verbose and not failures and not warnings:
					info_notes = notes.get('info', [])
					if info_notes:
						yield Tag(
							category='info',
							name='ssh_encryption',
							match=target,
							extra_data={
								'algorithm': algorithm,
								'info': info_notes
							}
						)

			# Process MAC algorithms
			mac_list = data.get('mac', [])
			for mac in mac_list:
				algorithm = mac.get('algorithm', '')
				notes = mac.get('notes', {})
				failures = notes.get('fail', [])
				warnings = notes.get('warn', [])

				# Create vulnerabilities for failures
				for failure in failures:
					yield Vulnerability(
						name=f'SSH weak MAC algorithm: {algorithm}',
						matched_at=target,
						tags=['ssh', 'mac', 'authentication'],
						severity='high',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': failure,
							'type': 'mac'
						}
					)

				# Create vulnerabilities for warnings
				for warning in warnings:
					yield Vulnerability(
						name=f'SSH MAC algorithm warning: {algorithm}',
						matched_at=target,
						tags=['ssh', 'mac', 'authentication'],
						severity='medium',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': warning,
							'type': 'mac'
						}
					)

				# Create info tags for successful algorithms if verbose
				if verbose and not failures and not warnings:
					info_notes = notes.get('info', [])
					if info_notes:
						yield Tag(
							category='info',
							name='ssh_mac',
							match=target,
							extra_data={
								'algorithm': algorithm,
								'info': info_notes
							}
						)

			# Process key exchange algorithms
			kex_list = data.get('kex', [])
			for kex in kex_list:
				algorithm = kex.get('algorithm', '')
				notes = kex.get('notes', {})
				failures = notes.get('fail', [])
				warnings = notes.get('warn', [])

				# Create vulnerabilities for failures
				for failure in failures:
					yield Vulnerability(
						name=f'SSH weak key exchange algorithm: {algorithm}',
						matched_at=target,
						tags=['ssh', 'kex', 'key-exchange'],
						severity='high',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': failure,
							'type': 'kex'
						}
					)

				# Create vulnerabilities for warnings
				for warning in warnings:
					yield Vulnerability(
						name=f'SSH key exchange algorithm warning: {algorithm}',
						matched_at=target,
						tags=['ssh', 'kex', 'key-exchange'],
						severity='medium',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': warning,
							'type': 'kex'
						}
					)

				# Create info tags for successful algorithms if verbose
				if verbose and not failures and not warnings:
					info_notes = notes.get('info', [])
					if info_notes:
						yield Tag(
							category='info',
							name='ssh_kex',
							match=target,
							extra_data={
								'algorithm': algorithm,
								'info': info_notes
							}
						)

			# Process host key algorithms
			key_list = data.get('key', [])
			for key in key_list:
				algorithm = key.get('algorithm', '')
				notes = key.get('notes', {})
				failures = notes.get('fail', [])
				warnings = notes.get('warn', [])

				# Create vulnerabilities for failures
				for failure in failures:
					yield Vulnerability(
						name=f'SSH weak host key algorithm: {algorithm}',
						matched_at=target,
						tags=['ssh', 'host-key'],
						severity='high',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': failure,
							'type': 'host_key'
						}
					)

				# Create vulnerabilities for warnings
				for warning in warnings:
					yield Vulnerability(
						name=f'SSH host key algorithm warning: {algorithm}',
						matched_at=target,
						tags=['ssh', 'host-key'],
						severity='medium',
						confidence='high',
						provider='ssh_audit',
						extra_data={
							'algorithm': algorithm,
							'issue': warning,
							'type': 'host_key'
						}
					)

				# Create info tags for successful algorithms if verbose
				if verbose and not failures and not warnings:
					info_notes = notes.get('info', [])
					if info_notes:
						yield Tag(
							category='info',
							name='ssh_host_key',
							match=target,
							extra_data={
								'algorithm': algorithm,
								'info': info_notes
							}
						)

			# Add banner info if verbose
			if verbose:
				yield Tag(
					category='info',
					name='ssh_banner',
					match=target,
					extra_data={
						'software': software,
						'protocol': banner.get('protocol', ''),
						'raw': banner.get('raw', '')
					}
				)
