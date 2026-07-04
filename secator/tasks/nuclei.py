import shlex

from secator.config import CONFIG
from secator.cve import extract_software_and_version
from secator.decorators import task

# fmt: off
from secator.definitions import (
	CONFIDENCE, CVSS_SCORE, CVSS_VECTOR, DELAY, DESCRIPTION, EPSS_SCORE, EXTRA_DATA, FOLLOW_REDIRECT, HEADER, HOST,
	HOST_PORT, ID, IMPACT, IP, MATCHED_AT, NAME, OPT_NOT_SUPPORTED, PERCENT, PROVIDER, PROXY, RATE_LIMIT, REFERENCES,
	REMEDIATION, RETRIES, SEVERITY, TAGS, THREADS, TIMEOUT, URL, USER_AGENT
)
# fmt: on
from secator.output_types import Progress, Tag, Technology, Vulnerability
from secator.serializers import JSONSerializer
from secator.tasks._categories import VulnMulti


def output_discriminator(self, item):
	"""Discriminate between Tag and Vulnerability based on severity."""
	if 'percent' in item:
		return Progress
	severity = item.get('info', {}).get('severity', '').lower()
	if severity == 'info':
		return Tag
	return Vulnerability


@task()
class nuclei(VulnMulti):
	"""Fast and customisable vulnerability scanner based on simple YAML based DSL."""

	cmd = 'nuclei'
	input_types = [HOST, HOST_PORT, IP, URL]
	output_types = [Vulnerability, Tag, Technology, Progress]
	tags = ['vuln', 'scan']
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-jsonl'
	input_chunk_size = 20
	opts = {
		'automatic_scan': {'is_flag': True, 'short': 'as', 'help': 'Automatic web scan using wappalyzer technology detection to tags mapping'},  # noqa: E501
		'bulk_size': {'type': int, 'short': 'bs', 'help': 'Maximum number of hosts to be analyzed in parallel per template'},  # noqa: E501
		'dast': {'is_flag': True, 'default': False, 'help': 'Enable DAST fuzzing templates (required to fuzz OpenAPI/Swagger endpoints)'},  # noqa: E501
		'debug': {'type': str, 'help': 'Debug mode'},
		'display_templates': {'is_flag': True, 'default': False, 'short': 'dt', 'help': 'Display loaded template names.'},
		'exclude_severity': {'type': str, 'short': 'es', 'help': 'Exclude severity'},
		'exclude_tags': {'type': str, 'short': 'etags', 'help': 'Exclude tags'},
		'hang_monitor': {'is_flag': True, 'short': 'hm', 'default': True, 'help': 'Enable nuclei hang monitoring'},
		'headless_bulk_size': {'type': int, 'short': 'hbs', 'help': 'Maximum number of headless hosts to be analzyed in parallel per template'},  # noqa: E501
		'input_mode': {'type': str, 'short': 'im', 'help': 'Mode of input file (list, burp, jsonl, yaml, openapi, swagger)'},
		'interactsh_server': {'type': str, 'default': None, 'short': 'iserver', 'help': 'InteractSH server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)'},  # noqa: E501
		'interactsh_token': {'type': str, 'default': None, 'short': 'itoken', 'help': 'InteractSH auth token for self-hosted instance'},  # noqa: E501
		'no_interactsh': {'is_flag': True, 'default': False, 'short': 'ni', 'help': 'Disable InteractSH server for OAST testing, exclude OAST based templates'},  # noqa: E501
		'logs': {'is_flag': True, 'internal': True, 'display': True, 'help': 'Log errors (-elog) and traces (-tlog) to output dir'},  # noqa: E501
		'new_templates': {'type': str, 'short': 'nt', 'help': 'Run only new templates added in latest nuclei-templates release'},  # noqa: E501
		'no_httpx': {'is_flag': True, 'short': 'nh', 'help': 'Disable httpx probing for non-url inputs'},
		'omit_raw': {'is_flag': True, 'short': 'or', 'default': True, 'help': 'Omit requests/response pairs in the JSON, JSONL, and Markdown outputs (for findings only)'},  # noqa: E501
		'response_size_read': {'type': int, 'default': CONFIG.http.response_max_size_bytes, 'help': 'Max body size to read (bytes)'},  # noqa: E501
		'severity': {'type': str, 'short': 's', 'help': 'Templates to run based on severity. Possible values: info, low, medium, high, critical, unknown'},  # noqa: E501
		'stats': {'is_flag': True, 'short': 'stats', 'default': True, 'help': 'Display statistics about the running scan'},
		'stats_json': {'is_flag': True, 'short': 'sj', 'default': True, 'help': 'Display statistics in JSONL(ines) format'},
		'stats_interval': {'type': str, 'short': 'si', 'help': 'Number of seconds to wait between showing a statistics update'},  # noqa: E501
		'store_responses': {'is_flag': True, 'short': 'sr', 'default': CONFIG.http.store_responses, 'help': 'Store reponses'},
		'tags': {'type': str, 'help': 'Tags'},
		'templates': {'type': str, 'short': 't', 'help': 'Templates'},
		'template_id': {'type': str, 'short': 'tid', 'help': 'Template id'},
		'template_condition': {'type': str, 'short': 'tc', 'help': 'Templates to run based on expression condition (ex: "contains(id, "ssh")")'},  # noqa: E501
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
		'display_templates': 'vv',
		'exclude_tags': 'exclude-tags',
		'exclude_severity': 'exclude-severity',
		'templates': 't',
		'response_size_read': 'rsr',
		'store_responses': 'sr',
		'template_condition': 'tc',
	}
	opt_value_map = {
		'tags': lambda x: ','.join(x) if isinstance(x, list) else x,
		'templates': lambda x: ','.join(x) if isinstance(x, list) else x,
		'exclude_tags': lambda x: ','.join(x) if isinstance(x, list) else x,
		'severity': lambda x: ','.join(x) if isinstance(x, list) else x,
		'exclude_severity': lambda x: ','.join(x) if isinstance(x, list) else x,
	}
	item_loaders = [JSONSerializer()]
	output_discriminator = output_discriminator
	output_map = {
		Vulnerability: {
			ID: lambda x: nuclei.id_extractor(x),
			NAME: lambda x: x['info']['name'],
			DESCRIPTION: lambda x: x['info'].get('description'),
			SEVERITY: lambda x: x['info'][SEVERITY],
			CONFIDENCE: lambda x: 'high',
			CVSS_SCORE: lambda x: float(x['info'].get('classification', {}).get('cvss-score') or 0),
			CVSS_VECTOR: lambda x: x['info'].get('classification', {}).get('cvss-metrics') or '',
			EPSS_SCORE: lambda x: float(x['info'].get('classification', {}).get('epss-score') or 0),
			IMPACT: lambda x: x['info'].get('impact') or '',
			REMEDIATION: lambda x: x['info'].get('remediation') or '',
			MATCHED_AT: 'matched-at',
			IP: 'ip',
			TAGS: lambda x: x['info']['tags'],
			REFERENCES: lambda x: [nuclei.get_github_template_url(x)] + x['info'].get('reference', []),
			EXTRA_DATA: lambda x: nuclei.extra_data_extractor(x),
			PROVIDER: 'nuclei',
		},
		Tag: {
			NAME: lambda x: nuclei.name_extractor(x),
			'match': 'matched-at',
			'value': lambda x: nuclei.value_extractor(x),
			'category': lambda x: 'info',
			EXTRA_DATA: lambda x: nuclei.extra_data_extractor(x, with_tags=True),
		},
		Technology: {
			'match': 'matched-at',
			'product': lambda x: nuclei.product_extractor(x),
			'version': lambda x: nuclei.version_extractor(x),
			EXTRA_DATA: lambda x: nuclei.extra_data_extractor(x),
		},
		Progress: {
			PERCENT: lambda x: int(x['percent']),
			EXTRA_DATA: lambda x: {k: v for k, v in x.items() if k not in ['percent']},
		},
	}
	install_version = 'v3.4.2'
	install_pre = {'*': ['git']}
	install_cmd = 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@[install_version]'
	github_handle = 'projectdiscovery/nuclei'
	install_post = {'*': 'nuclei -ut'}
	proxychains = False
	proxy_socks5 = True  # kind of, leaks data when running network / dns templates
	proxy_http = True  # same
	profile = 'extra_large'

	@staticmethod
	def on_init(self):
		store_responses = self.get_opt_value('store_responses')
		output_folder = shlex.quote(f'{self.reports_folder}/.outputs')
		if store_responses:
			self.cmd += f' -srd {output_folder}'
		logs = self.get_opt_value('logs')
		if logs:
			self.cmd += ' -ts'
			self.cmd += f' -elog {output_folder}/{self.fqn}_error.json'
			self.cmd += f' -tlog {output_folder}/{self.fqn}_trace.json'

	@staticmethod
	def id_extractor(item):
		cve_ids = item['info'].get('classification', {}).get('cve-id') or []
		if len(cve_ids) > 0:
			return cve_ids[0].upper()
		return None

	@staticmethod
	def extra_data_extractor(item, with_tags=False):
		data = {}
		data['data'] = item.get('extracted-results', [])
		data['type'] = item.get('type', '')
		data['matcher_name'] = item.get('matcher-name', '')
		data['template_id'] = item['template-id']
		data['curl_command'] = item.get('curl-command', '')
		data['template_url'] = nuclei.get_github_template_url(item)
		for k, v in item.get('meta', {}).items():
			data['data'].append(f'{k}: {v}')
		data['metadata'] = item.get('metadata', {})
		if with_tags:
			data['tags'] = item.get('info', {}).get('tags', [])
		return data

	@staticmethod
	def get_github_template_url(item):
		template = item.get('template')
		template_url = item.get('template-url', '')
		if template_url.startswith('https://cloud.projectdiscovery.io') and template:
			template_url = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/' + template
		return template_url

	@staticmethod
	def value_extractor(item):
		values = item.get('extracted-results', '')
		if isinstance(values, list) and values:
			return '\n'.join(values)
		matcher_name = item.get('matcher-name', '')
		if matcher_name:
			return matcher_name
		return item['template-id']

	@staticmethod
	def product_extractor(item):
		tid = item['template-id']
		if '-detect' in tid:
			return tid.replace('-detect', '')
		val = nuclei.value_extractor(item).replace('_', ' ').replace('/', '').replace('-detect', '').replace('-version', '').replace('generic', '')  # noqa: E501
		product, _ = extract_software_and_version(val, postfix=True)
		if product is not None:
			return product
		return val

	@staticmethod
	def version_extractor(item):
		val = nuclei.value_extractor(item).replace('_', ' ').replace('/', '').replace('-detect', '').replace('-version', '').replace('generic', '')  # noqa: E501
		_, version = extract_software_and_version(val, postfix=True)
		return version

	@staticmethod
	def name_extractor(item):
		name = item['template-id']
		return name
