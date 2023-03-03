from secsy.definitions import *
from secsy.tasks._categories import VulnCommand


class nuclei(VulnCommand):
	"""Fast and customisable vulnerability scanner based on simple YAML based
	DSL.
	"""
	cmd = 'nuclei -silent'
	file_flag = '-l'
	input_flag = '-u'
	input_chunk_size = 3 # TODO: figure out which chunk size is appropriate
	json_flag = '-json'
	opts = {
		'templates': {'type': str, 'help': 'Templates'},
		'tags': {'type': str, 'help': 'Tags'},
		'exclude_tags': {'type': str, 'help': 'Exclude tags'},
		'exclude_severity': {'type': str, 'help': 'Exclude severity'}
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'follow-redirects',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retries',
		THREADS: 'c',
		TIMEOUT: 'timeout',

		# nuclei opts
		'exclude_tags': 'exclude-tags',
		'exclude_severity': 'exclude-severity',
		'templates': 't'
	}
	opt_value_map = {
		'tags': lambda x: ','.join(x) if isinstance(x, list) else x,
		'templates': lambda x: ','.join(x) if isinstance(x, list) else x,
		'exclude_tags': lambda x: ','.join(x) if isinstance(x, list) else x,
	}
	output_map = {
		VULN_ID: lambda x: nuclei.id_extractor(x),
		VULN_PROVIDER: 'nuclei',
		VULN_NAME: lambda x: x['info']['name'],
		VULN_DESCRIPTION: lambda x: x['info'].get('description'),
		VULN_SEVERITY: lambda x: x['info'][VULN_SEVERITY],
		VULN_CONFIDENCE: lambda x: 'high',
		VULN_CVSS_SCORE: lambda x: x['info'].get('classification', {}).get('cvss-score', -1),
		VULN_MATCHED_AT:  'matched-at',
		VULN_TAGS: lambda x: x['info']['tags'],
		VULN_REFERENCES: lambda x: x['info']['reference'],
		VULN_EXTRACTED_RESULTS: lambda x: {'data': x.get('extracted-results', [])}
	}
	install_cmd = 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'

	@staticmethod
	def id_extractor(item):
		cve_ids = item['info'].get('classification', {}).get('cve-id') or []
		if len(cve_ids) > 0:
			return cve_ids[0]
		return None