import shutil

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.serializers import RegexSerializer
from secator.output_types import Vulnerability, Port, Url, Record, Ip, Tag, Info, Error
from secator.serializers import JSONSerializer


BBOT_MODULES = [
	"affiliates",
	# "ajaxpro",
	"anubisdb",
	"asn",
	"azure_realm",
	"azure_tenant",
	"badsecrets",
	"bevigil",
	"binaryedge",
	# "bucket_aws",
	"bucket_azure",
	"bucket_digitalocean",
	# "bucket_file_enum",
	"bucket_firebase",
	"bucket_google",
	"builtwith",
	"bypass403",
	"c99",
	"censys",
	"certspotter",
	# "chaos",
	"columbus",
	# "credshed",
	# "crobat",
	"crt",
	# "dastardly",
	# "dehashed",
	"digitorus",
	"dnscommonsrv",
	"dnsdumpster",
	# "dnszonetransfer",
	"emailformat",
	"ffuf",
	"ffuf_shortnames",
	# "filedownload",
	"fingerprintx",
	"fullhunt",
	"generic_ssrf",
	"git",
	"telerik",
	# "github_codesearch",
	"github_org",
	"gowitness",
	"hackertarget",
	"host_header",
	"httpx",
	"hunt",
	"hunterio",
	"iis_shortnames",
	# "internetdb",
	# "ip2location",
	"ipneighbor",
	"ipstack",
	"leakix",
	# "masscan",
	# "massdns",
	"myssl",
	# "newsletters",
	# "nmap",
	# "nsec",
	"ntlm",
	"nuclei",
	"oauth",
	"otx",
	"paramminer_cookies",
	"paramminer_getparams",
	"paramminer_headers",
	"passivetotal",
	"pgp",
	# "postman",
	"rapiddns",
	# "riddler",
	"robots",
	"secretsdb",
	"securitytrails",
	"shodan_dns",
	"sitedossier",
	"skymem",
	"smuggler",
	"social",
	"sslcert",
	# "subdomain_hijack",
	"subdomaincenter",
	# "sublist3r",
	"telerik",
	# "threatminer",
	"url_manipulation",
	"urlscan",
	"vhost",
	"viewdns",
	"virustotal",
	# "wafw00f",
	"wappalyzer",
	"wayback",
	"zoomeye"
]
BBOT_PRESETS = [
	'cloud-enum',
	'code-enum',
	'dirbust-heavy',
	'dirbust-light',
	'dotnet-audit',
	'email-enum',
	'iis-shortnames',
	'kitchen-sink',
	'paramminer',
	'spider',
	'subdomain-enum',
	'web-basic',
	'web-screenshots',
	'web-thorough'
]
BBOT_MODULES_STR = ' '.join(BBOT_MODULES)
BBOT_MAP_TYPES = {
	'IP_ADDRESS': Ip,
	'PROTOCOL': Port,
	'OPEN_TCP_PORT': Port,
	'URL': Url,
	'TECHNOLOGY': Tag,
	'ASN': Record,
	'DNS_NAME': Record,
	'WEBSCREENSHOT': Url,
	'VULNERABILITY': Vulnerability,
	'FINDING': Tag
}
BBOT_DESCRIPTION_REGEX = RegexSerializer(
	regex=r'(?P<name>[\w ]+): \[(?P<value>[^\[\]]+)\]',
	findall=True
)


def output_discriminator(self, item):
	_type = item.get('type')
	_message = item.get('message')
	if not _type and _message:
		return Error
	elif _type not in BBOT_MAP_TYPES:
		return None
	return BBOT_MAP_TYPES[_type]


@task()
class bbot(Command):
	"""Multipurpose scanner."""
	cmd = 'bbot -y --allow-deadly --force'
	json_flag = '--json'
	input_flag = '-t'
	file_flag = None
	version_flag = '--help'
	opts = {
		'modules': {'type': str, 'short': 'm', 'default': '', 'help': ','.join(BBOT_MODULES)},
		'presets': {'type': str, 'short': 'ps', 'default': 'kitchen-sink', 'help': ','.join(BBOT_PRESETS), 'shlex': False},
	}
	opt_key_map = {
		'modules': 'm',
		'presets': 'p'
	}
	opt_value_map = {
		'presets': lambda x: ' '.join(x.split(','))
	}
	item_loaders = [JSONSerializer()]
	output_types = [Vulnerability, Port, Url, Record, Ip]
	output_discriminator = output_discriminator
	output_map = {
		Ip: {
			'ip': lambda x: x['data'],
			'host': lambda x: x['data'],
			'alive': lambda x: True,
			'_source': lambda x: 'bbot-' + x['module']
		},
		Tag: {
			'name': 'name',
			'match': lambda x: x['data'].get('url') or x['data'].get('host'),
			'extra_data': 'extra_data',
			'_source': lambda x: 'bbot-' + x['module']
		},
		Url: {
			'url': lambda x: x['data'].get('url') if isinstance(x['data'], dict) else x['data'],
			'host': lambda x: x['resolved_hosts'][0] if 'resolved_hosts' in x else '',
			'status_code': lambda x: bbot.extract_status_code(x),
			'title': lambda x: bbot.extract_title(x),
			'screenshot_path': lambda x: x['data']['path'] if isinstance(x['data'], dict) else '',
			'_source': lambda x: 'bbot-' + x['module']
		},
		Port: {
			'port': lambda x: int(x['data']['port']) if 'port' in x['data'] else int(x['data'].split(':')[-1]),
			'ip': lambda x: [_ for _ in x['resolved_hosts'] if not _.startswith('::')][0],
			'state': lambda x: 'OPEN',
			'service_name': lambda x: x['data']['protocol'] if 'protocol' in x['data'] else '',
			'cpes': lambda x: [],
			'host': lambda x: x['data']['host'] if isinstance(x['data'], dict) else x['data'].split(':')[0],
			'extra_data': 'extra_data',
			'_source': lambda x: 'bbot-' + x['module']
		},
		Vulnerability: {
			'name': 'name',
			'match': lambda x: x['data'].get('url') or x['data']['host'],
			'extra_data': 'extra_data',
			'severity': lambda x: x['data']['severity'].lower()
		},
		Record: {
			'name': 'name',
			'type': 'type',
			'extra_data': 'extra_data'
		},
		Error: {
			'message': 'message'
		}
	}
	install_pre = {
		'apk': ['python3-dev', 'linux-headers', 'musl-dev', 'gcc', 'git', 'openssl', 'unzip', 'tar', 'chromium'],
		'*': ['gcc', 'git', 'openssl', 'unzip', 'tar', 'chromium']
	}
	install_cmd = 'pipx install bbot && pipx upgrade bbot'
	install_post = {
		'*': f'rm -fr {CONFIG.dirs.share}/pipx/venvs/bbot/lib/python3.12/site-packages/ansible_collections/*'
	}

	@staticmethod
	def on_json_loaded(self, item):
		_type = item.get('type')

		if not _type:
			yield item
			return

		# Set scan name and base path for output
		if _type == 'SCAN':
			self.scan_config = item['data']
			return

		if _type not in BBOT_MAP_TYPES:
			self._print(f'[bold orange3]Found unsupported bbot type: {_type}.[/] [bold green]Skipping.[/]', rich=True)
			return

		if isinstance(item['data'], str):
			item['name'] = item['data']
			yield item
			return

		item['extra_data'] = item['data']

		# Parse bbot description into extra_data
		description = item['data'].get('description')
		if description:
			del item['data']['description']
			match = BBOT_DESCRIPTION_REGEX.run(description)
			for chunk in match:
				key, val = tuple([c.strip() for c in chunk])
				if ',' in val:
					val = val.split(',')
				key = '_'.join(key.split(' ')).lower()
				item['extra_data'][key] = val

		# Set technology as name for Tag
		if item['type'] == 'TECHNOLOGY':
			item['name'] = item['data']['technology']
			del item['data']['technology']

		# If 'name' key is present in 'data', set it as name
		elif 'name' in item['data'].keys():
			item['name'] = item['data']['name']
			del item['data']['name']

		# If 'name' key is present in 'extra_data', set it as name
		elif 'extra_data' in item and 'name' in item['extra_data'].keys():
			item['name'] = item['extra_data']['name']
			del item['extra_data']['name']

		# If 'discovery_context' and no name set yet, set it as name
		else:
			item['name'] = item['discovery_context']

		# If a screenshot was saved, move it to secator output folder
		if item['type'] == 'WEBSCREENSHOT':
			from pathlib import Path
			path = Path.home() / '.bbot' / 'scans' / self.scan_config['name'] / item['data']['path']
			name = path.as_posix().split('/')[-1]
			secator_path = f'{self.reports_folder}/.outputs/{name}'
			yield Info(f'Copying screenshot {path} to {secator_path}')
			shutil.copy(path, secator_path)
			item['data']['path'] = secator_path

		yield item

	@staticmethod
	def extract_title(item):
		for tag in item['tags']:
			if 'http-title' in tag:
				title = ' '.join(tag.split('-')[2:])
				return title
		return ''

	@staticmethod
	def extract_status_code(item):
		for tag in item['tags']:
			if 'status-' in tag:
				return int([tag.split('-')[-1]][0])
		return 0
