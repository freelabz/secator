import json
import os
import shlex

from secator.config import CONFIG
from secator.decorators import task

# fmt: off
from secator.definitions import (
	DELAY, FOLLOW_REDIRECT, HEADER, OPT_NOT_SUPPORTED, OUTPUT_PATH, PATH, RATE_LIMIT, RETRIES, THREADS, TIMEOUT,
	USER_AGENT
)
# fmt: on
from secator.output_types import Error, Info, Vulnerability
from secator.tasks._categories import VulnCode

# How retire.js fingerprinted the library, mapped to our confidence. `filecontent` and `hash` match the actual
# bundle bytes; `filename` only trusts the file name, which a rename or a vendored path can fake.
RETIREJS_CONFIDENCE = {
	'filecontent': 'high',
	'hash': 'high',
	'filename': 'medium',
}

# retire.js advisory ids used when a vulnerability has neither a CVE nor a GHSA.
RETIREJS_LOCAL_IDS = ['retid', 'issue', 'bug', 'PR']


@task()
class retirejs(VulnCode):
	"""Scanner detecting the use of JavaScript libraries with known vulnerabilities."""

	cmd = 'retire'
	input_types = [PATH]
	output_types = [Vulnerability]
	tags = ['vuln', 'scan', 'js']
	input_flag = '--path'
	input_chunk_size = 1
	file_flag = None
	json_flag = None  # set in on_cmd: retire needs both --outputformat and --outputpath
	opt_prefix = '--'
	version_flag = '--version'
	opts = {
		'ext': {'type': str, 'help': 'Comma-separated list of JS file extensions to scan (default: "js")'},
		'ignore': {'type': str, 'help': 'Comma-delimited list of paths to ignore'},
		'ignorefile': {'type': str, 'help': 'Custom ignore file (defaults to .retireignore / .retireignore.json)'},
		'jsrepo': {'type': str, 'help': 'Local or internal version of the vulnerability repo'},
		'cachedir': {'type': str, 'help': 'Path to use for local cache instead of /tmp/.retire-cache'},
		'nocache': {'is_flag': True, 'default': False, 'help': "Don't use local cache"},
		'insecure': {'is_flag': True, 'default': False, 'help': 'Allow fetching the repo over insecure / self-signed TLS'},  # noqa: E501
		'deep': {'is_flag': True, 'default': False, 'help': 'Deep scan (slower and experimental)'},
		'include_osv': {'is_flag': True, 'default': False, 'help': 'Include OSV advisories in the output'},
	}
	opt_key_map = {
		'include_osv': 'includeOsv',
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	install_version = '5.7.0'
	install_github_bin = False  # retire.js ships on npm only, there is no GitHub release binary
	install_cmd_pre = {'apk': ['nodejs', 'npm'], 'brew': ['node'], '*': ['npm']}
	install_cmd = f'npm install -g --prefix {CONFIG.dirs.bin.parent} retire@[install_version]'
	github_handle = 'RetireJS/retire.js'

	@staticmethod
	def on_cmd(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.fqn}.json'
		self.output_path = output_path
		self.cmd += f' --outputformat json --outputpath {shlex.quote(self.output_path)}'

		# retire exits 13 when it finds vulnerabilities. Force 0 so a scan that worked and reported
		# findings isn't surfaced by secator as a failed command.
		self.cmd += ' --exitwith 0'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = json.load(f)

		for entry in results.get('data', []):
			matched_at = entry.get('file', '')
			for result in entry.get('results', []):
				component = result.get('component', '')
				version = result.get('version', '')
				detection = result.get('detection', '')
				for vuln in result.get('vulnerabilities', []):
					identifiers = vuln.get('identifiers', {})
					cves = identifiers.get('CVE') or []
					ghsa_id = identifiers.get('githubID', '')
					summary = identifiers.get('summary', '')
					vuln_id = cves[0] if cves else ghsa_id
					severity = (vuln.get('severity') or 'unknown').lower()

					extra_data = {
						'product': component,
						'version': version,
						'detection': detection,
					}
					if result.get('npmname'):
						extra_data['npmname'] = result['npmname']
					# retire reports the first *fixed* version as `below`, and an optional lower bound of the
					# affected range as `atOrAbove`.
					if vuln.get('below'):
						extra_data['versions_fixed'] = [vuln['below']]
					if vuln.get('atOrAbove'):
						extra_data['version_affected_from'] = vuln['atOrAbove']
					if vuln.get('cwe'):
						extra_data['cwe'] = vuln['cwe']
					if summary:
						extra_data['summary'] = summary
					for key in RETIREJS_LOCAL_IDS:
						if identifiers.get(key):
							extra_data[f'retire_{key.lower()}'] = identifiers[key]

					references = vuln.get('info') or []
					data = {
						'id': vuln_id,
						'name': vuln_id or summary or f'{component}-{version}',
						'matched_at': matched_at,
						'confidence': RETIREJS_CONFIDENCE.get(detection, 'low'),
						'severity': severity,
						'provider': 'retire.js',
						'cvss_score': -1,
						'references': references,
					}
					if vuln_id.startswith('CVE'):
						remote_data = VulnCode.lookup_cve(vuln_id)
						if remote_data:
							data.update(remote_data.toDict())
					elif vuln_id.startswith('GHSA'):
						data['provider'] = 'github.com'
						remote_data = VulnCode.lookup_cve_from_ghsa(vuln_id)
						if remote_data:
							data.update(remote_data)

					# The CVE / GHSA lookup returns a whole Vulnerability and clobbers these. retire.js is
					# authoritative for *where* the vulnerable library was found and for *how* it matched it
					# (the detection method), its advisory links are worth keeping alongside the ones the
					# lookup brings back, and its severity is the fallback whenever the advisory doesn't
					# carry one.
					data['matched_at'] = matched_at
					data['confidence'] = RETIREJS_CONFIDENCE.get(detection, 'low')
					data['references'] = list(dict.fromkeys(data.get('references', []) + references))
					data['severity'] = data['severity'] if data['severity'] not in ('', 'unknown') else severity
					data['extra_data'] = extra_data
					yield Vulnerability(**data)
