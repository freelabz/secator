import re

from secator.decorators import task
from secator.definitions import (
	HOST, HOST_PORT, IP, STRING, THREADS, HEADER, DELAY, FOLLOW_REDIRECT, PROXY, RATE_LIMIT, RETRIES, TIMEOUT,
	OPT_NOT_SUPPORTED, USER_AGENT,
)
from secator.output_types import Vulnerability, Tag, Technology, Warning
from secator.tasks._categories import Vuln
from secator.utils import autodetect_type


@task()
class nxc_smb(Vuln):
	"""NetExec (a.k.a nxc) is a network service exploitation tool that helps automate assessing the security of large networks. SMB Submodule."""  # noqa: E501
	cmd = 'nxc smb'
	encoding = 'ansi'  # nxc colorizes output; strip ANSI before parsing (CI forces color)
	input_chunk_size = 1
	input_types = [HOST, HOST_PORT, IP, STRING]
	output_types = [Vulnerability, Tag, Technology]
	ignore_return_code = True
	opt_prefix = '--'
	opts = {
		'username': {'type': str, 'short': 'u', 'default': '', 'help': 'Username'},
		'password': {'type': str, 'short': 'p', 'default': '', 'help': 'Password'},
		'domain': {'type': str, 'default': None, 'help': 'Domain'},
		'smb_port': {'type': int, 'default': 445, 'help': 'SMB port'},
		'dns_server': {'type': str, 'default': None, 'help': 'DNS server (default from system)'},
		'dns_timeout': {'type': int, 'default': None, 'help': 'DNS query timeout in seconds'},
		'cred_id': {'type': str, 'default': None, 'help': 'Database credential ID(s) to use for authentication'},
		'ignore_pw_decoding': {'is_flag': True, 'help': 'Ignore non UTF-8 characters when decoding the password file'},
		'no_bruteforce': {'is_flag': True, 'help': 'No spray when using file for username and password (user1 => password1, user2 => password2)'},  # noqa: E501
		'continue_on_success': {'is_flag': True, 'help': 'Continues auth attempts even after successes'},
		'kerberos': {'is_flag': True, 'help': 'Use Kerberos authentication'},
		'module': {'type': str, 'help': 'Module to use'},
		'module_option': {'type': str, 'help': 'Module option'},
		'get': {'type': str, 'help': 'Download a file'},
		'put': {'type': str, 'help': 'Upload a file (format: LOCAL_FILE REMOTE_FILE)'},
		'shares': {'is_flag': True, 'help': 'List shares'},
		'common_vulns': {'is_flag': True, 'default': True, 'internal': True, 'display': True, 'help': 'List SMB metdata and common vulns (null auth, v1 enabled, ...)'},  # noqa: E501
		'local_auth': {'is_flag': True, 'default': None, 'help': 'Local authentication'},
	}
	opt_key_map = {
		'username': '-u',
		'password': '-p',
		'domain': '-d',
		'module': '-M',
		'module_option': '-o',
		'smb_port': 'port',
		THREADS: 'threads',
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: 'jitter',
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	opt_value_map = {
		DELAY: lambda x: f'{str(x)}-{str(x)}',
	}
	github_handle = 'Pennyw0rth/NetExec'
	install_github_bin = False
	install_version = "30cf1465"
	install_cmd = "pipx install --force git+https://github.com/Pennyw0rth/NetExec@[install_version]"

	@staticmethod
	def on_cmd_opts(self, opts):
		if len(self.inputs) > 1:  # parent
			return opts
		if self.inputs:
			self.full_target = self.inputs[0]
		if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
			host, port = tuple(self.inputs[0].split(':'))
			self.cmd = self.cmd.replace(self.inputs[0], host)
			self.inputs[0] = host
			opts['smb_port']['value'] = int(port)
		self.login = False
		return opts

	@staticmethod
	def on_line(self, line):
		yield line
		get_mode = self.get_opt_value('get')
		put_mode = self.get_opt_value('put')
		module = self.get_opt_value('module')
		self.any_mode = (get_mode or put_mode or module)
		username = self.get_opt_value('username')

		# Errors
		error = '[-]' in line or 'ERROR' in line
		if error:
			if '[-]' in line:
				yield Warning(message=line.split('[-]')[-1].strip())
			else:
				yield Warning(message=line.split('ERROR')[-1].strip())

		# Login status (skip guest sessions: a (Guest) line does not confirm the configured creds)
		info = '[+]' in line
		if info and not self.any_mode and '(Guest)' not in line:
			username = self.get_opt_value('username')
			password = self.get_opt_value('password')
			message = line.split('[+]')[-1].strip()
			message = f'{username}:{password}'
			yield Tag(
				category='secret',
				match=self.full_target,
				name='smb_credentials',
				value=message,
				tags=['network', 'smb', 'login'],
				extra_data={
					'username': username,
					'password': password,
				}
			)

		# Anonymous login (vuln)
		if '(Guest)' in line and not self.any_mode and username:
			last_part = line.split('[+]')[-1].strip().replace('\\', '').replace(' (Guest)', '').split(':')
			username, password = tuple(last_part)
			yield Vulnerability(
				name='SMB - Credential Weakness',
				description='SMB Login for guest users is allowed.',
				impact='This can cause significant security risks which varies based on the SMB configuration.',
				remediation='Disable guest login.',
				cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
				cvss_score=6.5,
				severity='medium',
				confidence='high',
				matched_at=self.full_target,
				tags=['network', 'smb', 'default-login'],
				extra_data={
					'username': username,
				}
			)

		# # Generic info
		# info = '[*]' in line
		# if info and not self.any_mode:
		#     split = [c for c in line.split(' ') if c]
		#     from secator.rich import console
		#     console.print(split)
		#     if len(split) == 13: # generic Samba info
		#         pass

		# File list
		# if list_mode and line.startswith('FTP'):
		#     split = [c for c in line.split(' ') if c]
		#     if len(split) == 13: # file / dir listing
		#         _, _, _, _, perms, lcount, uid, gid, size, mod_month, mod_day, mod_time, name = tuple(split)
		#         tag_name = 'ftp_dir' if perms.startswith('d') else 'ftp_file'
		#         if name in ['.', '..']:
		#             return
		#         yield Tag(
		#             category='info',
		#             match=self.full_target,
		#             name=tag_name,
		#             value=name,
		#             extra_data={
		#                 'permissions': perms,
		#                 'link_count': lcount,
		#                 'uid': uid,
		#                 'gid': gid,
		#                 'size': size,
		#                 'last_updated': f'{mod_month} {mod_day} {mod_time}'
		#             }
		#         )

	@staticmethod
	def on_cmd_done(self):
		output_path = f'{self.reports_folder}/{self.fqn}_output.txt'
		with open(output_path, 'w') as f:
			f.write(self.output)
		parser = NXCParser(output_path)
		data = parser.parse()
		# self._print(data)
		common_vulns = self.get_opt_value('common_vulns')
		username_opt = self.get_opt_value('username')
		password_opt = self.get_opt_value('password')
		if common_vulns:
			# Valid credentials
			valid_creds = data.get('valid_creds', [])
			for cred in valid_creds:
				username = cred.get('username', '')
				password = cred.get('secret', '')
				yield Tag(
					category='secret',
					match=self.full_target,
					name='smb_credentials',
					value=f'{username}:{password}',
					tags=['network', 'smb', 'default-login'],
					extra_data={**cred, 'type': 'standard_credentials'}
				)
				if username != username_opt or password != password_opt:
					yield Vulnerability(
						name='SMB - Credential Weakness',
						matched_at=self.full_target,
						confidence='high',
						severity='high',
						cvss_score='CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
						description='An SMB server was accessed with easily guessed credentials.',
						impact='Users guessing the credentials can login on the SMB server and add malicious configurations',
						remediation='Update the password to one that cannot be cracked easily',
						extra_data={
							"data": {
								"username": username,
								"password": password
							}
						},
						references=[
							"https://github.com/p0dalirius/ApacheTomcatScanner/blob/main/apachetomcatscanner/data/credentials.json"
						],
						tags=['network', 'smb', 'default-login']
					)

			# Admin hosts
			admin_hosts = data.get('admin_hosts', [])
			for host in admin_hosts:
				username = host.get('username', '')
				password = host.get('secret', '')
				yield Tag(
					category='secret',
					match=self.full_target,
					name='smb_credentials',
					value=f'{username}:{password}',
					tags=['network', 'smb', 'admin-login'],
					extra_data={**host, 'type': 'admin_credentials'}
				)
				if username != username_opt or password != password_opt:
					yield Vulnerability(
						name='SMB - Credential Weakness',
						matched_at=self.full_target,
						confidence='high',
						severity='high',
						cvss_vec='CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
						cvss_score=8.5,
						description='An SMB server was accessed with easily guessed credentials.',
						impact='Users guessing the credentials can login on the SMB server and add malicious configurations',
						remediation='Update the password to one that cannot be cracked easily',
						tags=['network', 'smb', 'default-login'],
						extra_data={
							"data": {
								"username": username,
								"password": password
							}
						},
						references=[
							"https://github.com/p0dalirius/ApacheTomcatScanner/blob/main/apachetomcatscanner/data/credentials.json"
						]
					)

			# Hosts
			for host in data.get('hosts', []):
				smb_version = host.get('smb_version')
				signing = host.get('signing')  # None when NetExec omitted the field
				yield Tag(
					match=self.full_target,
					category='info',
					name='smb_info',
					value='data',
					tags=['network', 'smb'],
					extra_data={
						'hostname': host.get('hostname'),
						'os': host.get('os').split(' - ')[0],
						'smb_service_enabled': smb_version,
						'signing_enabled': signing,
					}
				)
				if signing is False:
					yield Vulnerability(
						name='SMB - Message Signing Not Required',
						description=(
							'The remote SMB server is configured without the requirement for message signing. '
						),
						impact=(
							'This absence of a signing mandate creates a vulnerability that can be exploited by an '
							'unauthenticated, remote attacker. Such an attacker could leverage this weakness to initiate '
							'man-in-the-middle attacks, targeting the communication processes of the SMB server, potentially '
							'intercepting, or manipulating data transmitted between the server and its clients.'
						),
						remediation=(
							'Ensure that message signing is enabled in the host\'s settings. '
							'For Windows systems, this option is typically located in the policy setting labeled '
							'\'Microsoft network server: Digitally sign communications (always)\'.'
						),
						cvss_vec='CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
						cvss_score=6.4,
						severity='medium',
						matched_at=self.full_target,
						confidence='high',
						tags=['network', 'smb', 'signing'],
						extra_data={
							'version': smb_version,
						}
					)
				null_auth = host.get('null_auth', False)
				if null_auth:
					yield Vulnerability(
						name='SMB - Null Auth Login',
						description=(
							'SMB null sessions allow attackers to connect to the IPC$ share without valid credentials. '
						),
						impact=(
							'This legacy vulnerability enables the unauthorized enumeration of users, groups, and '
							'password policies during network reconnaissance.'
						),
						remediation='Disable SMB Null sessions ASAP',
						cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
						cvss_score=5.3,
						severity='medium',
						matched_at=self.full_target,
						confidence='high',
						references=[
							'https://www.paloaltonetworks.com/cyberpedia/what-are-smb-null-sessions'
						],
						tags=['network', 'smb', 'unauth', 'default-login'],
					)
				if smb_version == 'v1':
					yield Vulnerability(
						name='SMB - v1 Service Enabled',
						description=(
							'SMB v1 has significant security vulnerabilities and is vulnerable to various attacks. '
						),
						impact=(
							'If SMBv1 is exploited, attackers can gain full control of your computer, potentially allowing them to access '
							'programs, view, change, steal, or delete data, and create new accounts'
						),
						remediation='Disable SMB version 1 ASAP',
						cvss_vec='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
						cvss_score=3.7,
						severity='low',
						matched_at=self.full_target,
						confidence='high',
						references=[
							'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server'  # noqa: E501
						],
						tags=['network', 'smb', 'deprecated'],
					)

		# SMB Shares
		shares_opt = self.get_opt_value('shares')
		if shares_opt:
			shares_data = data.get('shares', [])
			for share in shares_data:
				share_extra = {k: v for k, v in share.items() if k not in ['share', 'ip']}
				share_extra['username'] = self.get_opt_value('username')
				yield Tag(
					category='info',
					match=self.full_target,
					name='smb_share',
					value=share['share'],
					tags=['network', 'smb', 'share'],
					extra_data=share_extra,
				)
			if shares_data and username_opt in [None, '', 'guest']:
				yield Vulnerability(
					name='SMB - Unauthenticated Access To Network Share',
					matched_at=self.full_target,
					confidence='high',
					severity='high',
					extra_data={
						'username': username_opt
					},
					cvss_vec='CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
					cvss_score=8.5,
					description='One or multiple SMB share were accessed unauthenticated.',
					tags=['network', 'smb', 'share', 'unauth', 'default-login']
				)


# NetExec (NXC) Parser
# Handles all common nxc output formats: smb, ldap, winrm, mssql, rdp
from typing import Dict  # noqa: E402


class NXCParser:
	"""
	Parses NetExec (nxc) output files.

	Supports output from:
		nxc smb   10.10.10.0/24 -u user -p pass
		nxc smb   10.10.10.0/24 -u user -p pass --shares
		nxc smb   10.10.10.0/24 -u user -p pass --sessions
		nxc smb   10.10.10.0/24 -u user -p pass --pass-pol
		nxc ldap  10.10.10.5    -u user -p pass --active-users
		nxc winrm 10.10.10.0/24 -u user -p pass
		nxc smb   10.10.10.0/24 -u user -H <hash>   (PTH)

	Save output with:
		nxc smb 10.10.10.0/24 -u user -p pass --shares 2>&1 | tee nxc_out.txt
	"""

	# ── Compiled patterns ──────────────────────────────────────────────────────
	# Host column: IPv4 dotted-quad or an IPv6 literal (hex groups + ::)
	_IP = r"(?P<ip>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f:]+:[0-9A-Fa-f:]*)"
	# SMB host line:
	# SMB  10.10.10.5  445  DC01  [*] Windows 10.0 Build 17763 (name:DC01) (domain:corp.local)
	_RE_HOST = re.compile(
		r"(?:SMB|LDAP|WINRM|MSSQL|RDP)\s+" +
		_IP + r"\s+" +
		r"(?P<port>\d+)\s+"
		r"(?P<hostname>\S+)\s+"
		r"\[\*\]\s+(?P<info>.+)"
	)

	# Auth result:
	# SMB  10.10.10.5  445  DC01  [+] corp.local\svc-sql:ServicePass2024! (Pwn3d!)
	# SMB  10.10.10.5  445  DC01  [-] corp.local\jsmith:wrongpass
	_RE_AUTH = re.compile(
		r"(?:SMB|LDAP|WINRM|MSSQL|RDP)\s+" +
		_IP + r"\s+" +
		r"\d+\s+\S+\s+"
		r"(?P<status>\[.\])\s+"
		r"(?P<domain>[^\\]+)\\(?P<user>\S+?):(?P<secret>\S+)"
		r"(?P<pwned>\s+\(Pwn3d!\))?"
	)

	# Share line:
	# SMB  10.10.10.5  445  DC01  SYSVOL  READ,WRITE
	_RE_SHARE = re.compile(
		r"(?:SMB|LDAP)\s+" +
		_IP + r"\s+" +
		r"\d+\s+\S+\s+"
		r"(?P<share>\S+)\s+"
		r"(?P<perms>READ(?:,WRITE)?|WRITE|NO ACCESS)"
	)

	# Session line:
	# SMB  10.10.10.5  445  DC01  jsmith
	_RE_SESSION = re.compile(
		r"(?:SMB)\s+" +
		_IP + r"\s+" +
		r"\d+\s+\S+\s+"
		r"(?P<user>[a-zA-Z0-9._-]+)\s*$"
	)

	# Password policy lines
	_RE_POL_MIN = re.compile(r"Minimum password length:\s*(\d+)")
	_RE_POL_HIST = re.compile(r"Password history length:\s*(\d+)")
	_RE_POL_LOCK = re.compile(r"Account lockout threshold:\s*(\S+)")
	_RE_POL_COMP = re.compile(r"Password Complexity Flags:\s*(.+)")

	# Local admin line (from --local-auth or Pwn3d!)
	_RE_ADMIN = re.compile(
		r"(?:SMB|WINRM)\s+" +
		_IP + r"\s+" +
		r"\d+\s+"
		r"(?P<hostname>\S+)\s+"
		r"\[.\]\s+.+\(Pwn3d!\)"
	)

	# Interesting share names
	INTERESTING_SHARES = {
		"SYSVOL", "NETLOGON", "C$", "ADMIN$", "IPC$",
		"BACKUP", "DATA", "SCRIPTS", "SHARE", "FILES",
		"TRANSFER", "IT", "FINANCE", "HR", "DOCS"
	}

	def __init__(self, filepath: str):
		self.filepath = filepath

	def parse(self) -> Dict:
		data = {
			"hosts":            [],   # all discovered hosts
			"admin_hosts":      [],   # hosts where we have admin (Pwn3d!)
			"valid_creds":      [],   # valid credentials found
			"shares":           [],   # share enumeration results
			"sessions":         [],   # active user sessions on hosts
			"password_policy":  {},   # domain password policy
			"protocols":        {},   # per-host protocol support
			"raw_lines":        0,
		}

		try:
			with open(self.filepath, "r", errors="ignore") as f:
				lines = f.readlines()
		except FileNotFoundError:
			return data

		data["raw_lines"] = len(lines)
		seen_hosts = set()
		seen_creds = set()

		for line in lines:
			line = line.strip()
			if not line:
				continue

			# ── Host discovery ─────────────────────────────────────────────
			m = self._RE_HOST.search(line)
			if m:
				ip = m.group("ip")
				hostname = m.group("hostname")
				info = m.group("info")

				# Parse Windows version from info string
				win_ver = ""
				vm = re.search(r"Windows\s+[\d.]+\s+Build\s+(\d+)", info)
				if vm:
					win_ver = self._build_to_version(vm.group(1))

				# Detect protocol from line start
				proto = line.split()[0].upper()

				# Parse signing explicitly; keep None when NetExec omits the field
				# so a missing value is never reported as "signing disabled".
				sm = re.search(r"signing\s*:\s*(True|False)", info, re.IGNORECASE)
				signing = (sm.group(1).lower() == "true") if sm else None

				if ip not in seen_hosts:
					seen_hosts.add(ip)
					data["hosts"].append({
						"ip":       ip,
						"hostname": hostname,
						"os":       win_ver or info[:60],
						"domain":   self._extract_domain(info),
						"signing":  signing,
						"null_auth": "Null Auth:True" in info or "Null Auth: True" in info,
						"smb_version": "v1" if "SMBv1:True" in info or "SMBv1: True" in info else "other"
					})

				# Track protocol support per host
				if ip not in data["protocols"]:
					data["protocols"][ip] = []
				if proto not in data["protocols"][ip]:
					data["protocols"][ip].append(proto)

			# ── Auth results ────────────────────────────────────────────────
			m = self._RE_AUTH.search(line)
			if m and m.group("status") == "[+]":
				ip = m.group("ip")
				user = m.group("user")
				secret = m.group("secret")
				domain = m.group("domain")
				pwned = bool(m.group("pwned"))

				cred_key = f"{domain}\\{user}:{secret}"
				if cred_key not in seen_creds:
					seen_creds.add(cred_key)
					data["valid_creds"].append({
						"ip":       ip,
						"domain":   domain,
						"username": user,
						"secret":   secret,
						"is_hash":  len(secret) == 32 and all(
										c in "0123456789abcdefABCDEF"
										for c in secret),
						"is_admin": pwned,
					})

				if pwned and ip not in [h["ip"] for h in data["admin_hosts"]]:
					# Find hostname
					hostname = next(
						(h["hostname"] for h in data["hosts"] if h["ip"] == ip),
						ip
					)
					data["admin_hosts"].append({
						"ip":       ip,
						"hostname": hostname,
						"domain":   domain,
						"username": user,
						"secret":   secret,
					})

			# ── Share enumeration ───────────────────────────────────────────
			m = self._RE_SHARE.search(line)
			if m:
				share = m.group("share").upper()
				perms = m.group("perms")
				ip = m.group("ip")

				if perms != "NO ACCESS":
					data["shares"].append({
						"ip":          ip,
						"share":       share,
						"permissions": perms,
						"interesting": share in self.INTERESTING_SHARES,
						"writable":    "WRITE" in perms,
					})

			# ── Active sessions ─────────────────────────────────────────────
			if "--sessions" in self.filepath.lower() or "session" in line.lower():
				m = self._RE_SESSION.search(line)
				if m:
					data["sessions"].append({
						"ip":   m.group("ip"),
						"user": m.group("user"),
					})

			# ── Admin hosts (Pwn3d! in any line) ───────────────────────────
			m = self._RE_ADMIN.search(line)
			if m:
				ip = m.group("ip")
				hostname = m.group("hostname")
				if ip not in [h["ip"] for h in data["admin_hosts"]]:
					data["admin_hosts"].append({
						"ip":       ip,
						"hostname": hostname,
						"domain":   "",
						"username": "",
						"secret":   "",
					})

			# ── Password policy ─────────────────────────────────────────────
			for pattern, key in [
				(self._RE_POL_MIN,  "min_length"),
				(self._RE_POL_HIST, "history"),
				(self._RE_POL_LOCK, "lockout_threshold"),
				(self._RE_POL_COMP, "complexity"),
			]:
				m = pattern.search(line)
				if m:
					data["password_policy"][key] = m.group(1).strip()

		return data

	# ── Helpers ────────────────────────────────────────────────────────────────
	def _extract_domain(self, info: str) -> str:
		m = re.search(r"domain[:\s]+([a-zA-Z0-9._-]+)", info, re.IGNORECASE)
		return m.group(1) if m else ""

	def _build_to_version(self, build: str) -> str:
		builds = {
			"17763": "Windows Server 2019 / Win10 1809",
			"19041": "Windows 10 2004",
			"19042": "Windows 10 20H2",
			"19043": "Windows 10 21H1",
			"19044": "Windows 10 21H2",
			"20348": "Windows Server 2022",
			"22000": "Windows 11 21H2",
			"22621": "Windows 11 22H2",
			"14393": "Windows Server 2016 / Win10 1607",
			"10586": "Windows 10 1511",
			"9600":  "Windows Server 2012 R2",
			"9200":  "Windows Server 2012",
			"7601":  "Windows Server 2008 R2",
		}
		return builds.get(build, f"Build {build}")

	def summary(self, data: Dict) -> str:
		"""Return a one-line summary of parse results."""
		return (
			f"{len(data['hosts'])} hosts  |  "
			f"{len(data['admin_hosts'])} admin  |  "
			f"{len(data['valid_creds'])} valid creds  |  "
			f"{len(data['shares'])} shares  |  "
			f"{len(data['sessions'])} sessions"
		)
