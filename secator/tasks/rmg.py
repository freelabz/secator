import re
import shlex
import click

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, IP
from secator.output_types import Vulnerability, Tag, Technology
from secator.runners import Command


RMG_MODES = [
	'enum',
	'scan',
]

RMG_BIN = rf"""
#!/bin/bash

java -jar {CONFIG.dirs.bin}/rmg.jar \$@
""".lstrip()


@task()
class rmg(Command):
	"""Java RMI vulnerability scanner and enumerator."""

	cmd = 'rmg'
	input_types = [IP, HOST, HOST_PORT]
	output_types = [Vulnerability, Tag, Technology]
	tags = ['rmi', 'java', 'network']
	input_chunk_size = 1
	ignore_return_code = True
	opt_prefix = '--'
	install_version = '5.1.0'
	opts = {
		'mode': {'type': click.Choice(RMG_MODES), 'default': 'enum', 'internal': True, 'display': True, 'help': f'Scan mode ({", ".join(RMG_MODES)})'},  # noqa: E501
		'rmi_port': {'type': int, 'default': 1090, 'internal': True, 'display': True},
	}
	# install_pre = {
	# 	'*': ['openjdk-8-jre']
	# }
	install_cmd = (
		'wget https://github.com/qtc-de/remote-method-guesser/releases/download/v[install_version]/rmg-[install_version]-jar-with-dependencies.jar && '  # noqa: E501
		f'mv rmg-[install_version]-jar-with-dependencies.jar {CONFIG.dirs.bin}/rmg.jar && '
		f'echo "{RMG_BIN}" > {CONFIG.dirs.bin}/rmg && '
		f'chmod +x {CONFIG.dirs.bin}/rmg'
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
			port = self.get_opt_value('rmi_port')
			replaced = f'{host} {port}'

		mode = shlex.quote(self.get_opt_value('mode'))
		self.cmd = self.cmd.replace('rmg ', f'rmg {mode} ')
		self.cmd = self.cmd.replace(self.inputs[0], replaced)

	@staticmethod
	def on_cmd_done(self):
		cleaned_output = _strip_ansi(self.output)
		mode = self.get_opt_value('mode')

		target = self.inputs[0]
		if ':' not in self.inputs[0]:
			target = self.inputs[0] + ':' + str(self.get_opt_value('rmi_port'))

		if mode == 'scan':
			json_output = parse_rmg_scan_output(cleaned_output)
			for endpoint in json_output.get('endpoints', []):
				current_target = f"{endpoint['host']}:{endpoint['port']}"
				services = [s.strip().lower() for s in endpoint['services']]

				for service in services:
					yield Technology(
						product=f"rmi-{service}",
						version=None,
						match=current_target
					)

				if 'dgc' in services:
					yield Vulnerability(
						name='Java RMI - Unauthenticated Access',
						description="The Distributed Garbage Collector (DGC) service is exposed.",
						impact="Potential remote code execution (RCE) via deserialization on the Java DGC.",
						remediation="Disable or restrict network access to the RMI Distributed Garbage Collector.",
						cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
						cvss_score=9.8,
						matched_at=current_target,
						severity='critical',
						confidence='high',
						tags=['java', 'rmi', 'dgc', 'unauth']
					)
				if 'registry' in services:
					yield Vulnerability(
						name='Java RMI - Unauthenticated Access',
						description="An unprotected Java RMI Registry was found.",
						impact="Allows attackers to list or bind malicious objects.",
						remediation="Implement proper firewall rules or enable SSL on the RMI registry.",
						cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
						cvss_score=6.5,
						matched_at=current_target,
						severity='medium',
						confidence='high',
						tags=['java', 'rmi', 'registry', 'unauth']
					)
				if 'activator' in services:
					yield Vulnerability(
						name='Java RMI - Unauthenticated Access',
						description="The Java RMI Activation system daemon (RMID) or Activator is exposed externally.",
						impact="Allows remote clients to trigger object activation.",
						remediation="Ensure the RMI Activator is not exposed to untrusted networks.",
						cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
						cvss_score=8.2,
						matched_at=current_target,
						severity='high',
						confidence='high',
						tags=['java', 'rmi', 'activator', 'unauth']
					)

		elif mode == 'enum':
			json_output = parse_rmg_enum_output(cleaned_output)

			# --- Bound names as Tags ---
			for entry in json_output.get("bound_names", []):
				# Simple name tag
				yield Tag(
					match=target,
					category='info',
					name='rmi_bound_name',
					value=entry['name'],
				)
				# Detailed stub tag if we have stub info
				if entry.get('stub_class'):
					yield Tag(
						match=entry.get('endpoint', target),
						category='info',
						name='rmi_bound_stub',
						value=entry['stub_class'],
						extra_data={
							'bound_name': entry['name'],
							'class': entry.get('stub_class'),
							'known_class': entry.get('known_class'),
							'csf': entry.get('csf'),
							'obj_id': entry.get('obj_id'),
							'endpoint': entry.get('endpoint'),
						}
					)

			# --- Configuration status Tags ---
			for config in json_output.get("configurations", []):
				yield Tag(
					match=target,
					category='info',
					name='rmi_configuration',
					value=config['option'],
					extra_data={
						'option': config['option'],
						'status': config['status'],
						'section': config.get('section', ''),
					}
				)

			# --- Vulnerability Status ---
			if json_output["jep290"].get("status") == "Vulnerable":
				yield Vulnerability(
					name='Java RMI - Missing JEP290 Deserialization Filtering',
					description="The Java RMI service does not have JEP290 serialization filtering enabled, allowing raw deserialization of arbitrary objects.",  # noqa: E501
					impact="Remote Code Execution (RCE) via deserialization.",
					remediation="Upgrade Java or configure JEP290 deserialization filters.",
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
					cvss_score=9.8,
					matched_at=target,
					severity='critical',
					confidence='high',
					tags=['java', 'rmi', 'vuln', 'registry', 'jep290', 'deserialization']
				)

			if json_output["jep290_bypass"].get("status") == "Vulnerable":
				yield Vulnerability(
					name='Java RMI - Registry JEP290 Bypass',
					description="The Java RMI Registry is vulnerable to a JEP290 bypass.",
					impact="Remote Code Execution (RCE) even with JEP290 filters active.",
					remediation="Apply the latest Java JDK/JRE updates to patch known bypass gadgets.",
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
					cvss_score=9.8,
					matched_at=target,
					severity='critical',
					confidence='high',
					tags=['java', 'rmi', 'vuln', 'registry', 'jep290', 'bypass']
				)

			if json_output["activation_system"].get("vuln_status") == "Vulnerable":
				yield Vulnerability(
					name='Java RMI - ActivationSystem Deserialization Allowed',
					description="The RMI Activation System accepts deserialization of arbitrary objects.",
					impact="Remote Code Execution (RCE) via malicious payload deserialization on the Activation System.",
					remediation="Disable RMID (RMI Activation System daemon) if not required, or restrict access.",
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
					cvss_score=9.8,
					matched_at=target,
					severity='critical',
					confidence='high',
					tags=['java', 'rmi', 'vuln', 'activation-system', 'deserialization']
				)

			if json_output["localhost_bypass"].get("status") == "Vulnerable":
				yield Vulnerability(
					name='Java RMI - Registry Localhost Bypass',
					id='CVE-2019-2684',
					description="The RMI registry is vulnerable to a localhost bypass technique.",
					impact="Remote attackers can bind, rebind or unbind RMI objects in the registry.",
					remediation="Apply vendor updates to address CVE-2019-2684.",
					cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
					cvss_score=9.1,
					matched_at=target,
					severity='high',
					confidence='high',
					tags=['java', 'rmi', 'vuln', 'registry', 'bypass']
				)


def _strip_ansi(text):
	return re.sub(r'\x1b(?:\[[0-9;]*m|\][^\x1b]*\x1b\\)', '', text)


def parse_rmg_scan_output(output):
	result = {
		"endpoints": []
	}
	hit_pattern = re.compile(
		r'HITHITHIT\s+Found\s+RMI\s+servicesss\s+on\s+([^\s:]+):(\d+)\s+([)]+)([^)]+)([)]+)'
	)

	for line in output.strip().split('\n'):
		match = hit_pattern.search(line)
		if match:
			host = match.group(1)
			port = match.group(2)
			services = [s.strip() for s in match.group(3).split(',')]
			result["endpoints"].append({
				"host": host,
				"port": port,
				"services": services
			})
	return result


def parse_rmg_enum_output(output):
	"""
	Parse rmg enum output into structured data.

	bound_names entries look like:
		[+]     - java.rmi.activation.ActivationSystem
		[+]             --> sun.rmi.server.Activation$ActivationSystemImpl_Stub (known class: RMI Activation System)
		[+]                 Endpoint: 172.17.0.2:1097  CSF: RMISocketFactory  ObjID: [0:0:0, 4]

	configurations entries are emitted for any section that contains a "Configuration Status:" line.

	vulnerability sections contain "Vulnerability Status: Vulnerable/Non Vulnerable".

	activation_system is special: it contains multiple "-->" lines each with their own
	"Vulnerability Status" and "Configuration Status".
	"""
	# Strip ANSI codes before any parsing
	output = _strip_ansi(output)

	result = {
		"bound_names": [],        # list of {name, stub_class, known_class, endpoint, csf, obj_id}
		"configurations": [],     # list of {section, option, status}
		"localhost_bypass": {"status": "Non Vulnerable"},
		"jep290": {"status": "Non Vulnerable"},
		"jep290_bypass": {"status": "Non Vulnerable"},
		"activation_system": {"vuln_status": "Non Vulnerable", "configs": []},
	}

	SECTION_HEADERS = [
		"RMI registry bound names:",
		"RMI server codebase enumeration:",
		"RMI server String unmarshalling enumeration:",
		"RMI server useCodebaseOnly enumeration:",
		"RMI registry localhost bypass enumeration",
		"RMI Security Manager enumeration:",
		"RMI server JEP290 enumeration:",
		"RMI registry JEP290 bypass enumeration:",
		"RMI ActivationSystem enumeration:",
	]

	def is_section_header(line):
		return any(h in line for h in SECTION_HEADERS)

	def get_section_name(line):
		for h in SECTION_HEADERS:
			if h in line:
				return h
		return None

	def parse_stub_line(line):
		"""Parse a '-->' stub line, return (stub_class, known_class)."""
		# Split on '-->' first, then extract class and descriptor
		arrow_part = line.split('-->')[1].strip()
		# Class name is the first token
		parts = arrow_part.split(' ', 1)
		if not parts:
			return None, None
		stub_class = parts[0].strip()
		known_class = None
		if len(parts) > 1:
			descriptor = parts[1].strip()
			# Descriptor looks like "(known class: RMI Activation System)" or "(unknown class)"
			# Strip the outer parentheses
			if descriptor.startswith('(') and ')' in descriptor:
				descriptor = descriptor[1:descriptor.rfind(')')].strip()
				if descriptor.startswith('known class:'):
					known_class = descriptor.replace('known class:', '').strip()
				else:
					known_class = descriptor  # "unknown class"
		return stub_class, known_class

	def parse_endpoint_line(line):
		"""Parse an 'Endpoint:' line, return (endpoint, csf, obj_id)."""
		ep_match = re.search(r'Endpoint:\s+(\S+)', line)
		csf_match = re.search(r'CSF:\s+(\S+)', line)
		# Greedy match up to last ']' on line to handle complex ObjIDs
		obj_match = re.search(r'ObjID:\s+(.+.+.+)\s*$', line)
		endpoint = ep_match.group(1) if ep_match else None
		csf = csf_match.group(1) if csf_match else None
		obj_id = obj_match.group(1) if obj_match else None
		return endpoint, csf, obj_id

	def get_option_label(lines, current_idx):
		"""Walk back from current_idx to find the nearest descriptive label."""
		for j in range(current_idx - 1, max(current_idx - 5, 0), -1):
			prev = lines[j].strip()
			if prev.startswith('[+]') and '-->' in prev:
				return prev.split('-->')[1].strip()
			elif prev.startswith('[+]') and re.search(r'\s-\s', prev) and '-->' not in prev:
				return re.split(r'\s-\s', prev, maxsplit=1)[1].strip()
		return None

	lines = output.strip().split('\n')
	i = 0

	while i < len(lines):
		line = lines[i].strip()

		# ------------------------------------------------------------------ #
		# RMI registry bound names
		# ------------------------------------------------------------------ #
		if "RMI registry bound names:" in line:
			i += 1
			current_entry = None

			while i < len(lines):
				current = lines[i].strip()

				if is_section_header(current):
					if current_entry:
						result["bound_names"].append(current_entry)
						current_entry = None
					i -= 1
					break

				# New bound name: "[+]   - <name>"  (no '-->' in line)
				if current.startswith('[+]') and re.search(r'\s-\s', current) and '-->' not in current:
					if current_entry:
						result["bound_names"].append(current_entry)
					bound_name = re.split(r'\s-\s', current, maxsplit=1)[1].strip()
					current_entry = {
						'name': bound_name,
						'stub_class': None,
						'known_class': None,
						'endpoint': None,
						'csf': None,
						'obj_id': None,
					}

				# Stub class line: "[+]     --> some.class.Name (known class: ...)"
				elif current.startswith('[+]') and '-->' in current and current_entry is not None:
					stub_class, known_class = parse_stub_line(current)
					current_entry['stub_class'] = stub_class
					current_entry['known_class'] = known_class

				# Endpoint line: "[+]         Endpoint: host:port  CSF: val  ObjID: [...]"
				elif current.startswith('[+]') and 'Endpoint:' in current and current_entry is not None:
					endpoint, csf, obj_id = parse_endpoint_line(current)
					current_entry['endpoint'] = endpoint
					current_entry['csf'] = csf
					current_entry['obj_id'] = obj_id

				i += 1

			# Save last entry if loop ended without hitting a section header
			if current_entry:
				result["bound_names"].append(current_entry)

		# ------------------------------------------------------------------ #
		# RMI registry localhost bypass (CVE-2019-2684)
		# ------------------------------------------------------------------ #
		elif "RMI registry localhost bypass enumeration" in line:
			i += 1
			while i < len(lines):
				current = lines[i].strip()
				if is_section_header(current):
					i -= 1
					break
				if "Vulnerability Status:" in current:
					result["localhost_bypass"]["status"] = current.split("Vulnerability Status:")[1].strip()
					break
				i += 1

		# ------------------------------------------------------------------ #
		# RMI server JEP290
		# ------------------------------------------------------------------ #
		elif "RMI server JEP290 enumeration:" in line:
			i += 1
			while i < len(lines):
				current = lines[i].strip()
				if is_section_header(current):
					i -= 1
					break
				if "Vulnerability Status:" in current:
					result["jep290"]["status"] = current.split("Vulnerability Status:")[1].strip()
					break
				i += 1

		# ------------------------------------------------------------------ #
		# RMI registry JEP290 bypass
		# ------------------------------------------------------------------ #
		elif "RMI registry JEP290 bypass enumeration:" in line:
			i += 1
			while i < len(lines):
				current = lines[i].strip()
				if is_section_header(current):
					i -= 1
					break
				if "Vulnerability Status:" in current:
					result["jep290_bypass"]["status"] = current.split("Vulnerability Status:")[1].strip()
					break
				i += 1

		# ------------------------------------------------------------------ #
		# RMI ActivationSystem — special: multiple --> lines each with their
		# own Vulnerability Status / Configuration Status, but also handles
		# the case where there are no --> lines and only a plain
		# "Configuration Status:" line.
		# Format A (activator present):
		#   --> Deserialization allowed    - Vulnerability Status: Vulnerable
		#   --> Client codebase disabled   - Configuration Status: Current Default
		# Format B (activator not present):
		#   - Caught NoSuchObjectException during activate call (activator not present).
		#     Configuration Status: Current Default
		# ------------------------------------------------------------------ #
		elif "RMI ActivationSystem enumeration:" in line:
			section_name = "RMI ActivationSystem enumeration:"
			i += 1
			while i < len(lines):
				current = lines[i].strip()
				if is_section_header(current):
					i -= 1
					break
				# Format A: --> lines with inline status
				if '-->' in current:
					arrow_content = current.split('-->')[1].strip()
					parts = re.split(r'\s+-\s+', arrow_content, maxsplit=1)
					if len(parts) == 2:
						option_label = parts[0].strip()
						status_part = parts[1].strip()
						if "Vulnerability Status:" in status_part:
							result["activation_system"]["vuln_status"] = status_part.split("Vulnerability Status:")[1].strip()
						elif "Configuration Status:" in status_part:
							config_status = status_part.split("Configuration Status:")[1].strip()
							result["activation_system"]["configs"].append({
								"option": option_label,
								"status": config_status,
							})
				# Format B: plain "Configuration Status:" line (activator not present)
				elif "Configuration Status:" in current:
					config_status = current.split("Configuration Status:")[1].strip()
					option_label = get_option_label(lines, i) or section_name
					result["activation_system"]["configs"].append({
						"option": option_label,
						"status": config_status,
					})
					# Also store in configurations for Tag emission
					result["configurations"].append({
						"section": section_name,
						"option": option_label,
						"status": config_status,
					})
				i += 1

		# ------------------------------------------------------------------ #
		# All other sections: collect Configuration Status lines as Tags
		# ------------------------------------------------------------------ #
		elif is_section_header(line):
			section_name = get_section_name(line)
			i += 1
			while i < len(lines):
				current = lines[i].strip()
				if is_section_header(current):
					i -= 1
					break
				if "Configuration Status:" in current:
					config_status = current.split("Configuration Status:")[1].strip()
					option_label = get_option_label(lines, i) or section_name
					result["configurations"].append({
						"section": section_name,
						"option": option_label,
						"status": config_status,
					})
				i += 1
			continue  # skip the i += 1 at the bottom since we already advanced

		i += 1

	return result
