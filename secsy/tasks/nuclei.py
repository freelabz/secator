from secsy.decorators import task
from secsy.definitions import (DELAY, FOLLOW_REDIRECT, HEADER,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, VULN_CONFIDENCE,
							   CVSS_SCORE, DESCRIPTION,
							   VULN_EXTRACTED_RESULTS, ID,
							   VULN_MATCHED_AT, NAME, PROVIDER,
							   REFERENCES, VULN_SEVERITY, TAGS, USER_AGENT)
from secsy.output_types import Vulnerability, Progress
from secsy.tasks._categories import VulnMulti


@task()
class nuclei(VulnMulti):
	"""Fast and customisable vulnerability scanner based on simple YAML based
	DSL.
	"""
	cmd = 'nuclei -silent -sj -si 20 -hm'
	file_flag = '-l'
	input_flag = '-u'
	input_chunk_size = 1000
	json_flag = '-jsonl'
	opts = {
		'templates': {'type': str, 'short': 't', 'help': 'Templates'},
		'tags': {'type': str, 'help': 'Tags'},
		'exclude_tags': {'type': str, 'short': 'etags', 'help': 'Exclude tags'},
		'exclude_severity': {'type': str, 'short': 'es', 'help': 'Exclude severity'}
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
		USER_AGENT: OPT_NOT_SUPPORTED,

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
	output_types = [Vulnerability, Progress]
	output_map = {
		Vulnerability: {
			ID: lambda x: nuclei.id_extractor(x),
			PROVIDER: 'nuclei',
			NAME: lambda x: x['info']['name'],
			DESCRIPTION: lambda x: x['info'].get('description'),
			VULN_SEVERITY: lambda x: x['info'][VULN_SEVERITY],
			VULN_CONFIDENCE: lambda x: 'high',
			CVSS_SCORE: lambda x: x['info'].get('classification', {}).get('cvss-score') or 0,
			VULN_MATCHED_AT:  'matched-at',
			TAGS: lambda x: x['info']['tags'],
			REFERENCES: lambda x: x['info']['reference'],
			VULN_EXTRACTED_RESULTS: lambda x: {'data': x.get('extracted-results', [])}
		},
		Progress: {
			'extra_data': lambda x: {k: v for k, v in x.items() if k not in ['duration', 'errors', 'percent']}
		}
	}
	ignore_return_code = True
	install_cmd = 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'

	@staticmethod
	def id_extractor(item):
		cve_ids = item['info'].get('classification', {}).get('cve-id') or []
		if len(cve_ids) > 0:
			return cve_ids[0]
		return None
