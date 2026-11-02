import click
import re
import shlex

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import IP, HOST, HOST_PORT
from secator.output_types import Tag, Vulnerability, Technology, Warning
from secator.runners import Command


BEANSHOOTER_MODES = [
	'enum',
	'info',
]

BEANSHOOTER_BIN = rf"""
#!/bin/bash

java -jar {CONFIG.dirs.bin}/beanshooter.jar \$@
""".lstrip()


@task()
class beanshooter(Command):
	"""JMX enumeration and attacking tool."""

	input_types = [IP, HOST, HOST_PORT]
	output_types = [Vulnerability, Tag, Technology]
	tags = ['jmx', 'java', 'network']
	input_chunk_size = 1
	cmd = 'beanshooter'
	ignore_return_code = True
	opt_prefix = '--'
	opts = {
		'mode': {'type': click.Choice(BEANSHOOTER_MODES), 'default': 'enum', 'internal': True, 'display': True, 'help': f'Scan mode ({", ".join(BEANSHOOTER_MODES)})'},  # noqa: E501
		'jmx_port': {'type': int, 'default': 1099, 'internal': True, 'display': True},
		'ssl': {'is_flag': True, 'default': None, 'help': 'use SSL for connections'}
	}
	install_version = '4.1.0'
	# beanshooter is a Java jar wrapped by a `java -jar` shell script, so a JRE must
	# be present. JRE package names differ per distro (verified in containers), so
	# map them per package manager instead of a single apt-only name.
	install_pre = {
		'apt': ['default-jre-headless'],
		'apk': ['openjdk17-jre-headless'],
		'yum|dnf': ['java-latest-openjdk-headless'],
		'zypper': ['java-headless'],
		'pacman': ['jre-openjdk-headless'],
		'brew': ['openjdk'],
	}
	install_cmd = (
		'wget https://github.com/qtc-de/beanshooter/releases/download/v[install_version]/beanshooter-[install_version]-jar-with-dependencies.jar && '  # noqa: E501
		f'mv beanshooter-[install_version]-jar-with-dependencies.jar {CONFIG.dirs.bin}/beanshooter.jar && '
		f'echo "{BEANSHOOTER_BIN}" > {CONFIG.dirs.bin}/beanshooter && '
		f'chmod +x {CONFIG.dirs.bin}/beanshooter'
	)

	@staticmethod
	def on_cmd(self):
		if len(self.inputs) > 1 or len(self.inputs) == 0:
			return
		split = self.inputs[0].split(':')
		if len(split) == 2:
			replaced = self.inputs[0].replace(':', ' ')
		elif len(split) == 1:
			host = split[0]
			port = self.get_opt_value('jmx_port')
			replaced = f'{host} {port}'
		mode = shlex.quote(self.get_opt_value('mode'))
		self.cmd = self.cmd.replace('beanshooter ', f'beanshooter {mode} ')
		self.cmd = self.cmd.replace(self.inputs[0], replaced)

	@staticmethod
	def on_cmd_done(self):
		json_output = parse_beanshooter_output(_strip_ansi(self.output))
		# self._print(json_output)
		target = self.inputs[0]
		if ':' not in self.inputs[0]:
			target = self.inputs[0] + ':' + str(self.get_opt_value('jmx_port'))
		for key, value in json_output.items():
			if key == 'warnings':
				for warning in value:
					yield Warning(message=warning)
			if key == 'jmx_endpoint' and value.get("target", ''):
				yield Technology(
					product='java rmi',
					version=None,
					match=value['target']
				)
			if key == 'unauthorized_access' and value.get('status', '') == 'Vulnerable':
				yield Vulnerability(
					name='Java JMX - Unauthenticated Access',
					description="Remote MBean server does not require authentication.",
					impact="This can allow attackers to upload MBeans to the target server.",
					remediation="Force authenticated access for the MBean server.",
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
					cvss_score=7.3,
					matched_at=target,
					severity='high',
					confidence='high',
					tags=['java', 'jmx', 'mbean', 'unauth', 'vuln']
				)
			elif key == 'preauth_deserialization' and value.get('payload_accepted', False) is True:
				yield Vulnerability(
					name='Java JMX - Random payload allowed',
					description="Remote MBean server accepts random payload classes.",
					impact="This can allow malicious attackers to upload and/or trigger MBeans to gain elevated access.",
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
					cvss_score=9.8,
					matched_at=target,
					severity='critical',
					confidence='high',
					tags=['java', 'jmx', 'mbean', 'unauth', 'vuln']
				)
			elif key == 'mbeans' and value.get('total_count', 0) > 0:
				bean_classes = sorted(set(b['class'] for b in value.get('beans', []) if 'class' in b))
				for bean in bean_classes:
					yield Tag(
						match=target,
						category='info',
						name='jmx_bean',
						value=bean
					)
			elif key == 'tomcat_users' and value:
				for data in value:
					username = data.get('username', '')
					password = data.get('password', '')
					value = data.get('roles')
					yield Tag(
						match=target,
						category='secret',
						name='tomcat_credentials',
						value=f'{username}:{password}',
						extra_data=data
					)


def _strip_ansi(text):
	return re.sub(r'\x1b(?:\[[0-9;]*m|\][^\x1b]*\x1b\\)', '', text)


def parse_beanshooter_output(output):
	result = {
		"jmx_endpoint": {},
		"unauthorized_access": {},
		"preauth_deserialization": {},
		"mbeans": {},
		"tomcat_users": [],
		"warnings": []
	}

	lines = output.strip().split('\n')
	i = 0

	while i < len(lines):
		line = lines[i].strip()

		# Parse warnings
		if lines[i].strip().startswith('[-]'):
			warning = ""
			while i < len(lines) and lines[i].strip().startswith('[-]'):
				warning += lines[i].split('[-] ')[-1] + "\n"
				i += 1
			result['warnings'].append(warning)

		# Parse unauthorized access
		if "Checking available bound names:" in line:
			i += 1
			while i < len(lines) and lines[i].strip().startswith('[+]'):
				if "JMX endpoint" in lines[i]:
					result["jmx_endpoint"]["target"] = lines[i].split(': ')[-1].rstrip(')')
					break
				i += 1
			continue

		# Parse unauthorized access
		if "Checking for unauthorized access:" in line:
			i += 1
			while i < len(lines) and lines[i].strip().startswith('[+]'):
				if "does not require authentication" in lines[i]:
					result["unauthorized_access"]["requires_auth"] = False
				elif "Vulnerability Status:" in lines[i]:
					status = lines[i].split("Vulnerability Status:")[1].strip()
					result["unauthorized_access"]["status"] = status
					break
				i += 1
			continue

		# Parse pre-auth deserialization
		elif "Checking pre-auth deserialization behavior:" in line:
			i += 1
			while i < len(lines) and lines[i].strip().startswith('[+]'):
				if "rejected the payload class" in lines[i]:
					result["preauth_deserialization"]["payload_accepted"] = False
					break
				elif "accepted the payload class" in lines[i]:
					i += 1
					status = lines[i].split("Configuration Status:")[1].strip()
					result["preauth_deserialization"]["payload_accepted"] = True
					result["preauth_deserialization"]["status"] = status
					break
				i += 1
			continue

		# Parse MBeans info
		elif "Checking available MBeans:" in line:
			i += 2
			while i < len(lines) and lines[i].strip().startswith('[+]'):
				if "MBeans are currently registred" in lines[i]:
					total_match = re.search(r'(\d+) MBeans are currently registred', lines[i])
					if total_match:
						result["mbeans"]["total_count"] = int(total_match.group(1))
				elif "Listing" in lines[i] and "non default MBeans:" in lines[i]:
					non_default_match = re.search(r'Listing (\d+) non default MBeans:', lines[i])
					if non_default_match:
						result["mbeans"]["non_default_count"] = int(non_default_match.group(1))
						result["mbeans"]["beans"] = []
				elif 'org.apache' in lines[i] or 'javax.' in lines[i] or 'sun.' in lines[i]:
					# Parse individual MBean
					bean_match = re.search(r'- (.+?) (.+?)(.+?)(.+?)', lines[i])
					if bean_match:
						result["mbeans"]["beans"].append({
							"class": bean_match.group(1),
							# "name": bean_match.group(2)
						})
				else:
					break
				i += 1
			continue

		# Parse tomcat users
		elif "Enumerating tomcat users:" in line:
			i += 1
			while i < len(lines) and lines[i].strip().startswith('[+]'):
				if "Listing" in lines[i] and "tomcat users:" in lines[i]:
					users_match = re.search(r'Listing (\d+) tomcat users:', lines[i])
					if users_match:
						result["tomcat_users_count"] = int(users_match.group(1))
				elif "Username:" in lines[i]:
					user = {}
					user["username"] = lines[i].split("Username:")[1].strip()
					i += 1

					# Get password
					if i < len(lines) and "Password:" in lines[i]:
						user["password"] = lines[i].split("Password:")[1].strip()
						i += 1

					# Get roles
					user["roles"] = []
					if i < len(lines) and "Roles:" in lines[i]:
						i += 1
						while i < len(lines) and 'Users:type=Role' in lines[i]:
							role_match = re.search(r'rolename="([^"]+)"', lines[i])
							if role_match:
								user["roles"].append(role_match.group(1))
							i += 1

					result["tomcat_users"].append(user)
					continue
				i += 1
			continue

		i += 1

	return result
