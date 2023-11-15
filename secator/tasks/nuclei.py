from secator.decorators import task
from secator.definitions import (CONFIDENCE, CVSS_SCORE, DELAY, DESCRIPTION,
								 EXTRA_DATA, FOLLOW_REDIRECT, HEADER, ID, IP,
								 MATCHED_AT, NAME, OPT_NOT_SUPPORTED, PERCENT,
								 PROVIDER, PROXY, RATE_LIMIT, REFERENCES,
								 RETRIES, SEVERITY, TAGS, THREADS, TIMEOUT,
								 USER_AGENT, DEFAULT_NUCLEI_FLAGS)
from secator.output_types import Progress, Vulnerability
from secator.tasks._categories import VulnMulti


@task()
class nuclei(VulnMulti):
	"""Fast and customisable vulnerability scanner based on simple YAML based DSL."""
	cmd = f'nuclei {DEFAULT_NUCLEI_FLAGS}'
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-jsonl'
	opts = {
		'templates': {'type': str, 'short': 't', 'help': 'Templates'},
		'tags': {'type': str, 'help': 'Tags'},
		'exclude_tags': {'type': str, 'short': 'etags', 'help': 'Exclude tags'},
		'exclude_severity': {'type': str, 'short': 'es', 'help': 'Exclude severity'},
		'template_id': {'type': str, 'short': 'id', 'help': 'Template id'},
		'debug': {'type': str, 'help': 'Debug mode'},
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
			NAME: lambda x: nuclei.name_extractor(x),
			DESCRIPTION: lambda x: x['info'].get('description'),
			SEVERITY: lambda x: x['info'][SEVERITY],
			CONFIDENCE: lambda x: 'high',
			CVSS_SCORE: lambda x: x['info'].get('classification', {}).get('cvss-score') or 0,
			MATCHED_AT:  'matched-at',
			IP: 'ip',
			TAGS: lambda x: x['info']['tags'],
			REFERENCES: lambda x: x['info'].get('reference', []),
			EXTRA_DATA: lambda x: nuclei.extra_data_extractor(x),
			PROVIDER: 'nuclei',
		},
		Progress: {
			PERCENT: lambda x: int(x['percent']),
			EXTRA_DATA: lambda x: {k: v for k, v in x.items() if k not in ['duration', 'errors', 'percent']}
		}
	}
	ignore_return_code = True
	install_cmd = 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'
	proxychains = False
	proxy_socks5 = True  # kind of, leaks data when running network / dns templates
	proxy_http = True  # same
	profile = 'cpu'

	@staticmethod
	def id_extractor(item):
		cve_ids = item['info'].get('classification', {}).get('cve-id') or []
		if len(cve_ids) > 0:
			return cve_ids[0]
		return None

	@staticmethod
	def extra_data_extractor(item):
		data = {}
		data['data'] = item.get('extracted-results', [])
		data['template_id'] = item['template-id']
		data['template_url'] = item['template-url']
		return data

	@staticmethod
	def name_extractor(item):
		name = item['template-id']
		matcher_name = item.get('matcher-name', '')
		if matcher_name:
			name += f':{matcher_name}'
		return name
