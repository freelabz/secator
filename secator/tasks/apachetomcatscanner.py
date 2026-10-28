import json
import os
import shlex

from secator.decorators import task

# fmt: off
from secator.definitions import (
	DELAY, FOLLOW_REDIRECT, HEADER, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT, URL,
	USER_AGENT
)
# fmt: on
from secator.output_types import Vulnerability, Technology, Url, Tag, Warning
from secator.tasks._categories import Vuln


@task()
class apachetomcatscanner(Vuln):
	"""Apache Tomcat servers vulnerability scanner."""

	cmd = 'apachetomcatscanner'
	input_types = [URL]
	output_types = [Vulnerability, Technology, Url, Tag]
	tags = ['tomcat', 'java', 'http']
	input_flag = '-tu'
	file_flag = '-tU'
	version_flag = '--help'
	opts = {
		'only_http': {'is_flag': True, 'default': False, 'help': 'Scan only with HTTP scheme'},
		'only_https': {'is_flag': True, 'default': False, 'help': 'Scan only with HTTPs scheme'},
	}
	opt_key_map = {
		THREADS: '-T',
		TIMEOUT: '-rt',
		HEADER: '-H',
		# proxy is split into --proxy-ip/--proxy-port, no single-string mapping
		PROXY: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
		'only_http': '--only-http',
		'only_https': '--only-https',
	}
	install_version = '3.8.2'
	install_cmd = 'pipx install apachetomcatscanner==[install_version] --force'
	install_github_bin = False
	github_handle = 'p0dalirius/ApacheTomcatScanner'

	@staticmethod
	def on_cmd(self):
		# Always list CVEs (+ descriptions) and export to JSON for parsing.
		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.fqn}.json'
		self.cmd += (
			' --list-cves --verbose --debug --show-cves-descriptions --no-colors'
			f' --export-json {shlex.quote(self.output_path)}'
		)

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Warning(message=f'Could not find JSON results in {self.output_path}')
			return
		with open(self.output_path, 'r') as f:
			results = json.load(f)
		# Structure: {ip: {port: {target, scheme, version, cves: [...]}}}
		for ports in results.values():
			for node in ports.values():
				version = node.get('version')
				scheme = node.get('scheme', 'http')
				target = node.get('target', '')
				port = node.get('computer_port', '')
				manager_url = node.get('manager_url', '')
				manager_accessible = node.get('manager_accessible', False)
				credentials_found = node.get('credentials_found', [])
				matched_at = f'{scheme}://{target}:{port}' if port else f'{scheme}://{target}'
				yield Technology(
					match=matched_at,
					product='apache tomcat',
					version=version,
				)
				if manager_url:
					yield Url(
						url=manager_url,
						status_code=200 if manager_accessible else 0,
						verified=manager_accessible,
						tags=['apache', 'tomcat', 'manager', 'admin'],
						tech=[f'apache tomcat/{version}'] if version else []
					)
				# bugfix: credentials_found in JSON is a list of lists...
				if isinstance(credentials_found, list) and len(credentials_found) == 1:
					credentials_found = credentials_found[0]
				for cred in credentials_found:
					if isinstance(cred, dict):
						username = cred.get('username', '')
						password = cred.get('password', '')
						yield Tag(
							category='secret',
							name='tomcat_credentials',
							match=manager_url,
							value=f'{username}:{password}',
							tags=['web', 'tomcat', 'login'],
							extra_data=cred
						)
						yield Vulnerability(
							name='Apache - Credential Weakness',
							matched_at=manager_url,
							ip=target,
							confidence='high',
							severity='high',
							cvss_vec='CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
							cvss_score=8.5,
							description='An Apache server was accessed with easily guessed credentials.',
							impact='Users guessing the credentials can login on Tomcat admin UI and add malicious configurations',
							remediation='Update the password to one that cannot be cracked easily',
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
				cves = node.get('cves', [])
				for entry in cves:
					yield apachetomcatscanner._make_vuln(entry, version, matched_at)

	@staticmethod
	def _make_vuln(entry, version, matched_at):
		cve = entry.get('cve', {})
		cvss = entry.get('cvss', {})
		cve_id = cve.get('id', '')
		try:
			cvss_score = float(cvss.get('score') or 0.0)
		except (TypeError, ValueError):
			cvss_score = 0.0
		criticity = (cvss.get('criticity') or '').lower()
		severity = criticity if criticity and criticity != 'none' else 'unknown'
		confidence = 'high' if cvss_score > 0 else 'low'
		extra_data = {'version': version}
		if cve.get('vuln_type'):
			extra_data['vuln_type'] = cve['vuln_type']
		# Keep the raw CVSS breakdown the tool provides (no vector string available).
		for k in ('access', 'complexity', 'confidentiality', 'integrity', 'availablility'):
			if cvss.get(k):
				extra_data[k] = cvss[k]
		return Vulnerability(
			id=cve_id,
			name=cve_id,
			matched_at=matched_at,
			provider='apachetomcatscanner',
			severity=severity,
			cvss_score=cvss_score,
			confidence=confidence,
			description=entry.get('description', ''),
			references=entry.get('references', []),
			tags=['tomcat'],
			extra_data=extra_data,
		)
