from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Vulnerability, Tag
from secator.definitions import HOST, IP, TIMEOUT
from secator.tasks._categories import Command
from secator.serializers import JSONSerializer


@task()
class sshaudit(Command):
	"""SSH server & client security auditing (banner, key exchange, encryption, mac, compression, etc)."""
	cmd = 'ssh-audit'
	input_types = [HOST, IP]
	output_types = [Vulnerability, Tag]
	tags = ['ssh', 'audit', 'security']
	item_loaders = [JSONSerializer()]
	input_flag = None
	file_flag = '-T'
	json_flag = '-j'
	ignore_return_code = True
	opt_prefix = '--'
	opts = {
		'ssh_port': {'type': int, 'short': 'sshp', 'default': 22, 'help': 'SSH port to connect to'},
		'ipv4': {'is_flag': True, 'short': '4', 'default': False, 'help': 'Enable IPv4 (order of precedence)'},
		'ipv6': {'is_flag': True, 'short': '6', 'default': False, 'help': 'Enable IPv6 (order of precedence)'},
		'batch': {'is_flag': True, 'short': 'b', 'default': False, 'help': 'Enable batch output for automated processing'},
		'client_audit': {'is_flag': True, 'short': 'c', 'default': False, 'help': 'Start a listening server for client auditing'},  # noqa: E501
		'level': {'type': str, 'short': 'l', 'default': None, 'help': 'Minimum output level (info, warn, fail)'},
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
		'ssh_port': '-p',
	}
	github_handle = 'jtesta/ssh-audit'
	install_github_bin = False
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
	def on_json_loaded(self, item):
		target = item.get('target', 'unknown')
		banner = item.get('banner', {})
		software = banner.get('software', 'unknown')

		yield Tag(
			category='info',
			name='ssh_banner',
			value=banner.get('raw', ''),
			match=target,
			extra_data={
				'software': software,
				'protocol': banner.get('protocol', ''),
			}
		)

		# Process CVEs
		cves = item.get('cves', [])
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
		enc_list = item.get('enc', [])
		for enc in enc_list:
			algorithm = enc.get('algorithm', '')
			notes = enc.get('notes', {})
			failures = notes.get('fail', [])
			warnings = notes.get('warn', [])

			# Create vulnerabilities for failures
			for failure in failures:
				yield Vulnerability(
					name='SSH weak encryption algorithm',
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
					name='SSH encryption algorithm warning',
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
			if not failures and not warnings:
				info_notes = ', '.join(notes.get('info', []))
				value = f'{algorithm} {info_notes}'
				yield Tag(
					category='info',
					name='ssh_encryption',
					value=value,
					match=target,
					extra_data={
						'algorithm': algorithm,
					}
				)

		# Process MAC algorithms
		mac_list = item.get('mac', [])
		for mac in mac_list:
			algorithm = mac.get('algorithm', '')
			notes = mac.get('notes', {})
			failures = notes.get('fail', [])
			warnings = notes.get('warn', [])

			# Create vulnerabilities for failures
			for failure in failures:
				yield Vulnerability(
					name='SSH weak MAC algorithm',
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
					name='SSH MAC algorithm warning',
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
			if not failures and not warnings:
				info_notes = ', '.join(notes.get('info', []))
				value = f'{algorithm} {info_notes}'
				yield Tag(
					category='info',
					name='ssh_mac',
					value=value,
					match=target,
					extra_data={
						'algorithm': algorithm,
					}
				)

		# Process key exchange algorithms
		kex_list = item.get('kex', [])
		for kex in kex_list:
			algorithm = kex.get('algorithm', '')
			notes = kex.get('notes', {})
			failures = notes.get('fail', [])
			warnings = notes.get('warn', [])

			# Create vulnerabilities for failures
			for failure in failures:
				yield Vulnerability(
					name='SSH weak key exchange algorithm',
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
					name='SSH key exchange algorithm warning',
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
			if not failures and not warnings:
				info_notes = ', '.join(notes.get('info', []))
				value = f'{algorithm} {info_notes}'
				yield Tag(
					category='info',
					name='ssh_kex',
					value=value,
					match=target,
					extra_data={
						'algorithm': algorithm,
					}
				)

		# Process host key algorithms
		key_list = item.get('key', [])
		for key in key_list:
			algorithm = key.get('algorithm', '')
			notes = key.get('notes', {})
			failures = notes.get('fail', [])
			warnings = notes.get('warn', [])

			# Create vulnerabilities for failures
			for failure in failures:
				yield Vulnerability(
					name='SSH weak host key algorithm',
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
					name='SSH host key algorithm warning',
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
			if not failures and not warnings:
				info_notes = ', '.join(notes.get('info', []))
				value = f'{algorithm} {info_notes}'
				yield Tag(
					category='info',
					name='ssh_host_key',
					match=target,
					value=value,
					extra_data={
						'algorithm': algorithm,
					}
				)
