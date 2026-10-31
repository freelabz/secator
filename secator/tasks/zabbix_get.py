import os
import re

from pathlib import Path

from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, IP, SLUG, STRING
from secator.output_types import Error, Vulnerability, Tag
from secator.runners import Command
from secator.utils import autodetect_type


HTTP_PROXY = os.environ.get('http_proxy')
HTTPS_PROXY = os.environ.get('https_proxy')

# Transport / protocol diagnostics that zabbix_get emits INSTEAD of an item value.
# These are NOT item data, so they must never be turned into a system.run /
# vfs.file.contents finding. zabbix_get prints its own transport failures as
# "zabbix_get [<pid>]: <reason>" lines (e.g. a connect/timeout error), and the
# agent returns protocol-level error markers (ZBX_NOTSUPPORTED, etc.) in-band.
# We classify at the on_cmd_done boundary because the process exit code is not
# finalized here and ignore_return_code=True would discard it anyway.
# Anchored / fixed-substring alternation only -> linear-time, ReDoS-safe.
ZABBIX_DIAGNOSTIC_RE = re.compile(
	r'(?im)'
	r'^\s*zabbix_get\s*\[\d+\]:'              # zabbix_get [12345]: <transport error>
	r'|zbx_notsupported'                      # agent: key not supported
	r'|zbx_error'                             # agent: generic protocol error
	r'|get value error'                       # zabbix_get: value retrieval failed
	r'|check access restrictions'             # agent: denied by AllowKey/DenyKey
	r'|cannot connect'                        # transport: connect failed
	r'|connection (?:refused|reset|timed out)'  # transport: connection failures
	r'|timeout while executing'               # transport: operation timeout
)


@task()
class zabbix_get(Command):
	"""Zabbix get is a command-line utility, which can be used to communicate with Zabbix agent and retrieve required information from the agent."""  # noqa: E501
	cmd = 'zabbix_get'
	# zabbix_get is NOT in the Debian/Ubuntu default repos (Zabbix ships its CLI
	# tools from repo.zabbix.com). It IS in the default repos of Alpine
	# (zabbix-utils), Fedora/RHEL/openSUSE (the `zabbix` package) and Arch
	# (zabbix-agent), and in Homebrew (`zabbix`). So:
	#   - non-apt package managers -> install_pre (the package ships zabbix_get),
	#   - apt (Debian/Ubuntu & derivatives) -> install_cmd that first registers the
	#     official Zabbix 7.0 repo for the detected distro+release, then installs
	#     zabbix-get. Keyed by distro *name* (install_cmd dicts match distro.name).
	install_pre = {
		'apk': ['zabbix-utils'],
		'brew': ['zabbix'],
		'pacman': ['zabbix-agent'],
		'yum|dnf|zypper': ['zabbix'],
	}
	# apt path needs wget + CA certs to fetch the zabbix-release .deb over HTTPS.
	install_cmd_pre = {
		'apt': ['wget', 'ca-certificates'],
	}
	install_cmd = {
		'ubuntu|debian|linuxmint|popos|kali': (
			'sh -c \''
			'set -e; . /etc/os-release; '
			# Run the privileged steps via sudo when not root (the installer runs
			# unprivileged in CI; a raw install_cmd is NOT auto-prefixed with sudo the
			# way install_pre/install_cmd_pre package installs are).
			'SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"; '
			# Ubuntu AND its derivatives (Mint/PopOS) all set ID_LIKE=debian, so we must
			# branch on UBUNTU_CODENAME (only set on the Ubuntu family) rather than
			# ID_LIKE: Ubuntu-family -> Ubuntu repo keyed by the *Ubuntu* release;
			# everything else (Debian, Kali) -> Debian repo keyed by the major version
			# (Kali is rolling/based on Debian testing, default to 13/trixie).
			# On a derivative (e.g. Linux Mint 21) VERSION_ID is the derivative version
			# (21), NOT the Ubuntu base (22.04), so deriving REL from VERSION_ID builds a
			# wrong Zabbix URL. Map UBUNTU_CODENAME -> Ubuntu release instead; UBUNTU_CODENAME
			# is always the *Ubuntu* base codename even on derivatives.
			'if [ -n "${UBUNTU_CODENAME:-}" ]; then '
			'  BASE=ubuntu; '
			'  case "$UBUNTU_CODENAME" in '
			'    focal) REL=20.04 ;; '
			'    jammy) REL=22.04 ;; '
			'    noble) REL=24.04 ;; '
			'    *) REL="$VERSION_ID" ;; '
			'  esac; '
			'  # On plain Ubuntu, VERSION_ID already matches the codename; fall back to it '
			'  # for unmapped (future) releases. On a derivative, VERSION_ID is the '
			'  # derivative version, so an unmapped codename may still mis-key -- extend '
			'  # the case list when Zabbix adds a new Ubuntu release. '
			'else '
			'  BASE=debian; REL="${VERSION_ID%%.*}"; [ -n "$REL" ] || REL=13; '
			'fi; '
			'DEB="zabbix-release_7.0-1+${BASE}${REL}_all.deb"; '
			'wget -q "https://repo.zabbix.com/zabbix/7.0/${BASE}/pool/main/z/zabbix-release/${DEB}" -O /tmp/zabbix-release.deb; '
			'$SUDO dpkg -i /tmp/zabbix-release.deb; '
			'$SUDO apt-get update; '
			'$SUDO apt-get install -y --no-install-recommends zabbix-get'
			'\''
		),
	}
	# zabbix_get ships from the OS package manager, not a GitHub release.
	install_github_bin = False
	input_flag = '-s'
	file_flag = None
	input_chunk_size = 1
	input_types = [HOST, HOST_PORT, IP, SLUG, STRING]
	output_types = [Vulnerability, Tag]
	opts = {
		'key': {'type': str, 'default': r"system.run[ls]", 'help': 'Key of the item to retrieve value for (e.g: system.run with ls, or vfs.file.contents of a path)'},  # noqa: E501
		'zabbix_port': {'type': int, 'default': 10050, 'help': 'Zabbix agent port'}
	}
	opt_key_map = {
		'zabbix_port': 'p',
		'key': 'k'
	}
	ignore_return_code = True

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		self.full_target = self.inputs[0]
		if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
			host, port = tuple(self.inputs[0].split(':'))
			self.cmd = self.cmd.replace(self.inputs[0], host)
			self.full_target = self.inputs[0]
			self.inputs[0] = host
			opts['zabbix_port']['value'] = int(port)
		return opts

	@staticmethod
	def on_cmd_done(self):
		key = self.get_opt_value('key')
		output = self.output or ''
		# zabbix_get's own return code is not yet available in this callback (it's
		# set after on_cmd_done), and ignore_return_code=True would zero it anyway,
		# so we must NOT gate on self.return_code. Instead classify the output itself.
		#
		# [B] Reject transport / protocol diagnostics BEFORE emitting any finding. A
		# nonempty transport diagnostic (a "zabbix_get [pid]: ..." line, a timeout, a
		# refused/reset connection, or an in-band ZBX_* protocol marker) is NOT item
		# data -- treating it as such would mint a high-confidence system.run /
		# vfs.file.contents finding from an error string. We match only Zabbix-specific
		# transport/protocol diagnostics, NOT generic strings like "permission denied",
		# which can legitimately appear in retrieved command output
		# (e.g. system.run[echo permission denied]) and must not suppress a real finding.
		if ZABBIX_DIAGNOSTIC_RE.search(output):
			# Surface the diagnostic so a failed/denied probe is never silent.
			yield Error(message=f'zabbix_get transport/protocol diagnostic: {output.strip()[:500]}')
			return
		# [C] Empty output is ambiguous: a successful wait-mode system.run can legitimately
		# return no data, but so can a silent failure. self.return_code is not finalized at
		# on_cmd_done, so there is no reliable success signal here to tell them apart.
		# We deliberately favour correctness (no false-positive RCE/LFI) over catching the
		# rare empty-but-successful case, and suppress empty output as a non-finding. This
		# is a documented, accepted limitation: an empty genuine success is not reported.
		if not output.strip():
			return
		if key.startswith('vfs.file.contents'):
			filepath = key.split('vfs.file.contents')[-1].rstrip(']').lstrip('[')
			yield Vulnerability(
				name='Zabbix - Local File Inclusion',
				description=(
					'It is possible to list folders and read files remotely using the Zabbix agent by using the official zabbix_get tool from the same editor. \n'  # noqa: E501
					'On the default Zabbix agent configuration, the "vfs.file.contents" key is disabled, which does not allow folder and file reads. \n'  # noqa: E501
					'This means that someone has modified the default server configuration so that this RCE becomes possible.'
				),
				impact=(
					'This can cause significant security risks which varies based on the user rights running the Zabbix agent:\n',
					'- Reading and exfiltrating files containing sensitive data (app and config files, environment variables, logs, SSH keys, certificates, ...)\n'  # noqa: E501
					'- Causing a Denial of Service\n'
					'- Executing custom code'
				),
				remediation=(
					'Disable remote command execution immediately in the Zabbix agent configuration by setting:\n'
					'- Setting `EnableRemoteCommands=0` (if Zabbix agent version < 5)\n'
					'- Adding an `AllowKey` whitelist in Zabbix agent configuration (see [instructions](https://www.zabbix.com/documentation/current/en/manual/config/items/restrict_checks)) (if Zabbix agent version >= 5.0+)'  # noqa: E501
				),
				cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
				cvss_score=7.5,
				severity='high',
				confidence='high',
				matched_at=self.full_target,
				extra_data={
					'key': key,
					'filepath': filepath
				},
				tags=['zabbix', 'lfi', 'vuln', 'unauth'],
			)
			safe_path = filepath.replace('/', '_')
			file_path = Path(self.reports_folder) / '.outputs' / f'{self.fqn}_{safe_path}'
			with file_path.open('w') as f:
				f.write(self.output)

		elif key.startswith('system.run'):
			cmd = key.split('system.run')[-1].rstrip(']').lstrip('[')
			yield Vulnerability(
				name='Zabbix - Remote Code Execution',
				description=(
					'It is possible to execute remote commands using the Zabbix agent by using the official zabbix_get tool from the same editor. \n'  # noqa: E501
					'On the default Zabbix agent configuration, the "system.run" key is disabled, which does not allow remote execution. \n'  # noqa: E501
					'This means that someone has modified the default server configuration so that this RCE becomes possible.'
				),
				impact=(
					'This can cause significant security risks which varies based on the user rights running the Zabbix agent:\n',
					'- Reading and exfiltrating files containing sensitive data (app and config files, environment variables, logs, SSH keys, certificates, ...)\n'  # noqa: E501
					'- Causing a Denial of Service\n'
					'- Executing custom code'
				),
				remediation=(
					'Disable remote command execution immediately in the Zabbix agent configuration by setting:\n'
					'- Setting `EnableRemoteCommands=0` (if Zabbix agent version < 5)\n'
					'- Adding an `AllowKey` whitelist in Zabbix agent configuration (see [instructions](https://www.zabbix.com/documentation/current/en/manual/config/items/restrict_checks)) (if Zabbix agent version >= 5.0+)'  # noqa: E501
				),
				cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
				cvss_score=9.8,
				severity='critical',
				confidence='high',
				matched_at=self.full_target,
				extra_data={
					'key': key,
					'command': cmd,
				},
				tags=['zabbix', 'rce', 'vuln', 'unauth'],
			)
			yield Tag(
				category='secret',
				name='Zabbix remote code execution output',
				value='\n' + self.output,
				match=self.full_target,
				extra_data={
					'command': cmd
				},
			)
