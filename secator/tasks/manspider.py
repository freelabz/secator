"""
manspider
-t 15
-d "dom000.prdinf"
-u "BFS81NU"
-p ""
--content "passw|pwd|secret|superadmin|admb|kdbx|pdtb"
--extensions ini cfg txt bak save sav ps1 ps bat sh bash config kdbx backup cer der cert pem properties cnf conf yaml yml xml  # noqa: E501
-m 5
-s 1M
-l [LOOT DIR] [IP/RANGE/FILE]
"""


from secator.decorators import task
from secator.definitions import CIDR_RANGE, HOST, HOST_PORT, IP, STRING
from secator.output_types import Tag, Vulnerability, Info
from secator.serializers import JSONSerializer
from secator.rich import console
from secator.runners import Command


@task()
class manspider(Command):
	"""Spider SMB shares for files and sensitive content across a network."""
	cmd = 'manspider'
	json_flag = '--json'
	input_types = [STRING, CIDR_RANGE, HOST, HOST_PORT, IP]
	output_types = [Tag, Vulnerability]
	item_loaders = [JSONSerializer()]
	opt_prefix = '--'
	opts = {
		'username': {'type': str, 'default': None, 'help': 'Username for authentication'},
		'password': {'type': str, 'default': None, 'help': 'Password for authentication'},
		'domain': {'type': str, 'default': None, 'help': 'Domain for authentication'},
		'max_depth': {'type': int, 'default': 10, 'help': 'Maximum depth to spider'},
		'hash': {'type': str, 'default': None, 'help': 'NTLM hash for authentication'},
		'kerberos': {'is_flag': True, 'default': False, 'help': 'Use Kerberos authentication'},
		'aes_key': {'type': str, 'default': None, 'help': 'AES key to use for Kerberos Authentication (128 or 256 bits)'},
		'dc_ip': {'type': str, 'default': None, 'help': 'IP Address of the domain controller. If omitted it will use the domain part (FQDN) of the target'},  # noqa: E501
		'threads': {'type': int, 'default': 5, 'help': 'Concurrent threads'},
		'filenames': {'type': str, 'default': None, 'help': 'Filter filenames using regex (space-separated)'},
		'extensions': {'type': str, 'default': None, 'help': 'Only show filenames with these extensions (space-separated)'},
		'exclude_extensions': {'type': str, 'default': None, 'help': 'Ignore files with these extensions (space-separated)'},
		'content': {'type': str, 'default': None, 'help': 'Search for file content using regex (space-separated)'},
		'sharenames': {'type': str, 'default': None, 'help': 'Only search shares with these names (space-separated)'},
		'exclude_sharenames': {'type': str, 'default': None, 'help': 'Do not search shares with these names (space-separated)'},  # noqa: E501
		'dirnames': {'type': str, 'default': None, 'help': 'Only search directories containing these strings (space-separated)'},  # noqa: E501
		'exclude_dirnames': {'type': str, 'default': None, 'help': 'Do not search directories containing these strings (space-separated)'},  # noqa: E501
		'no_download': {'is_flag': True, 'default': None, 'help': 'Do not download matching files'},
		'max_failed_logons': {'type': int, 'default': None, 'help': 'Limit failed logons'},
		'or_logic': {'is_flag': True, 'default': None, 'help': 'Use OR logic instead of AND'},
		'max_filesize': {'type': str, 'default': '10M', 'help': 'Do not retrieve files over thise size, e.g: "500K" or ".5M"'},  # noqa: E501
		'modified_after': {'type': str, 'default': None, 'help': 'Only show files modified after this date (format: YYYY-MM-DD)'},  # noqa: E501
		'modified_before': {'type': str, 'default': None, 'help': 'Only show files modified before this date (format: YYYY-MM-DD)'},  # noqa: E501
	}
	opt_key_map = {
		'max_depth': 'maxdepth',
	}
	install_cmd = "pipx install --force git+https://github.com/freelabz/MANSPIDER@feature/anon-share-enum-and-json-output"

	@staticmethod
	def on_cmd(self):
		self.loot_dir = f'{self.reports_folder}/.outputs'
		self.cmd += f' --loot-dir {self.loot_dir}'
		self.line_idx = 0
		self.secrets = []
		self.secrets_found = 0
		# Per-target counters, keyed by the 'host:port' target string emitted on
		# each output line. One manspider instance can receive up to 100 targets
		# in async runs, so access must be attributed to the target that produced
		# it rather than aggregated across the whole instance.
		self.shares_found = {}
		# Confirmed readable access (files listed / content matched), as opposed
		# to merely a share being enumerated (which can still be ACCESS_DENIED).
		self.access_confirmed = {}

	@staticmethod
	def on_start(self):
		console.print(Info(message=f'Loot directory set to {self.loot_dir}'))
		or_logic = self.get_opt_value('or_logic')
		matcher_names = ['filenames', 'extensions', 'content', 'sharenames', 'dirnames']
		matchers = {k: self.get_opt_value(k) for k in matcher_names}
		matchers_non_empty = [k for k, v in matchers.items() if v]
		matchers_str = ', '.join([f'[bold blue]{k}[/]' for k in matchers_non_empty])
		if or_logic:
			console.print(Info(message=f'Using [bold blue]OR[/] logic for matchers {matchers_str}'))
		else:
			console.print(Info(message=f'Using [bold blue]AND[/] logic for matchers {matchers_str}'))
		for name in matchers_non_empty:
			val = self.get_opt_value(name)
			val_str = ','.join([f'[bold gold3]{k}[/]' for k in val.split(' ')])
			console.print(Info(message=f'Searching for {name}: {val_str}'))

	@staticmethod
	def on_json_loaded(self, item):
		target = item['target'] + ':' + str(item['port'])
		share = item['share']
		if item['type'] == 'share':
			self.shares_found[target] = self.shares_found.get(target, 0) + 1
			yield Tag(
				match=target,
				category='info',
				name='smb_share',
				value=share,
				tags=['network', 'smb', 'share']
			)
		elif item['type'] == 'content_match':
			self.secrets_found += 1
			self.access_confirmed[target] = self.access_confirmed.get(target, 0) + 1
			for match in item['matches']:
				secret = Tag(
					match=target + '//' + item['share'] + '/' + item['path'],
					category='secret',
					name='smb_sensitive_data',
					value=match['match'],
					tags=['network', 'smb', 'secret'],
					extra_data={
						'target': target,
						'share': item['share'],
						'path': item['path'],
						'pattern': item['pattern'],
						'line': match['line'],
						'columns': str(match['column']) + ':' + str(match['end_column']),
					}
				)
				self.secrets.append(secret)
				yield secret
		elif item['type'] == 'file':
			self.access_confirmed[target] = self.access_confirmed.get(target, 0) + 1
			yield Tag(
				match=target,
				category='info',
				name='smb_share_file',
				value=item['path'],
				tags=['network', 'smb', 'file'],
				extra_data={
					'size': item['size'],
					'share': share
				}
			)

	@staticmethod
	def on_cmd_done(self):
		username = self.get_opt_value('username')
		password = self.get_opt_value('password')
		# Only report unauthenticated access once access is actually confirmed
		# (a file listed or content matched). A bare 'share' enumeration can still
		# return ACCESS_DENIED on listing, which is not unauthenticated access.
		# Attribute to the specific target that produced the access, not inputs[0],
		# since one instance can process many targets in async runs.
		if username in [None, '', 'guest']:
			for target in sorted(self.access_confirmed):
				if not self.shares_found.get(target):
					continue
				yield Vulnerability(
					name='SMB - Unauthenticated Share Access',
					matched_at=target,
					confidence='high',
					severity='high',
					extra_data={
						'username': username
					},
					cvss_score=8.5,
					cvss_vec='CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
					description='One or multiple SMB share were accessed unauthenticated.',
					tags=['network', 'smb', 'share', 'vuln', 'unauth', 'default-login']
				)
		if self.secrets_found > 0:
			tags = ['network', 'smb', 'secret', 'vuln']
			if not username and not password:
				tags.append('unauth')
			# Group secrets by the target that produced them, then by share, so each
			# affected target gets its own vulnerability matched at that target.
			targets = set(c.extra_data['target'] for c in self.secrets)
			for target in sorted(targets):
				target_secrets = [c for c in self.secrets if c.extra_data['target'] == target]
				share_names = set(c.extra_data['share'] for c in target_secrets)
				description = "The following shares contain files with sensitive information: "
				patterns = []
				for share in share_names:
					share_secrets = [c for c in target_secrets if c.extra_data['share'] == share]
					description += f"\n* {target}//{share}:"
					for secret in share_secrets:
						patterns.append(secret.value)
						description += f"\n\t* {secret.extra_data['pattern']} @ {secret.extra_data['path']}"
				yield Vulnerability(
					name='SMB - Secrets Detected',
					description=description,
					impact='Secrets can be exfiltrated and used for malicious purposes.',
					remediation='Remove the secrets from the affected share files ASAP.',
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
					cvss_score=7.7,
					matched_at=target,
					severity='critical',
					confidence='high',
					tags=tags,
					extra_data={
						'found': len(target_secrets),
						'patterns': list(set(patterns))
					}
				)
