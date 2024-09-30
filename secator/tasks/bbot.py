from secator.decorators import task
from secator.runners import Command
from secator.serializers import RegexSerializer
from secator.output_types import Vulnerability, Port, Url, Record, Ip, Tag


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
BBOT_MODULES_STR = ' '.join(BBOT_MODULES)
BBOT_MAP_TYPES = {
	'IP_ADDRESS': Ip,
	'PROTOCOL': Port,
	'OPEN_TCP_PORT': Port,
	'URL': Url,
	'TECHNOLOGY': Tag,
	# 'DNS_NAME': Record,
	'VULNERABILITY': Vulnerability,
	'FINDING': Tag
}
NUCLEI_DATA_REGEX = RegexSerializer(
	regex=r'template: \[(?P<template>[\w?-]+)\], name: \[(?P<name>[\w ]+)\]( Extracted Data: \[(?P<extracted_data>.*))?',
	fields=['template', 'name', 'extracted_data']
)


def output_discriminator(self, item):
	type_ = item.get('type')
	if not type_ in BBOT_MAP_TYPES:
		self._print(f'Found unsupported bbot type: {type_}', 'bold orange3')
		return None
	return BBOT_MAP_TYPES[item['type']]


@task()
class bbot(Command):
	cmd = f'bbot -y --allow-deadly --force'
	json_flag = '--json'
	input_flag = '-t'
	file_flag = None
	opts = {
		'modules': {'type': str, 'short': 'm', 'default': ','.join(BBOT_MODULES)}
	}
	opt_key_map = {
		'modules': 'm'
	}
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
			'name': lambda x: x['data']['name'],
			'match': lambda x: x['data']['url'],
			'extra_data': lambda x: x['data'],
			'_source': lambda x: 'bbot-' + x['module']
		},
		Url: {
			'url': 'data',
			'host': lambda x: x['resolved_hosts'][0],
			'status_code': lambda x: int([c.split('-')[-1] for c in x['tags'] if 'status-' in c][0]),
			'title': lambda x: [' '.join(c.split('-')[2:]) for c in x['tags'] if 'http-title-' in c][0],
			'_source': lambda x: 'bbot-' + x['module']
		},
		Port: {
			'port': lambda x: int(x['data']['port']) if 'port' in x['data'] else x['data'].split(':')[-1],
			'ip': lambda x: [_ for _ in x['resolved_hosts'] if not _.startswith('::')][0],
			'state': lambda x: 'OPEN',
			'service_name': lambda x: x['data']['protocol'] if 'protocol' in x['data'] else '',
			'cpes': lambda x: [],
			'host': lambda x: x['data']['host'] if isinstance(x['data'], dict) else x['data'].split(':')[0],
			'extra_data': lambda x: {},
			'_source': lambda x: 'bbot-' + x['module']
		},
		Vulnerability: {
			'name': lambda x: x['data']['name'],
			'extra_data': lambda x: x['data']
		}
	}
	install_cmd = 'pipx install bbot && pipx upgrade bbot'

	@staticmethod
	def on_json_loaded(self, item):
		if not isinstance(item['data'], dict):
			yield item
			return
		if not item['type'] in BBOT_MAP_TYPES:
			yield item
			return
		if item['module'] == 'nuclei':
			description = item['data']['description']
			output = list(NUCLEI_DATA_REGEX.run(description))[0]
			name = output['name']
			template = output['template']
			extracted_data = output['extracted_data']
			if extracted_data:
				if ',' in extracted_data:
					extracted_data = extracted_data.split(',')
				item['data']['data'] = extracted_data
			item['name'] = name
			item['data']['template_id'] = template
			del item['data']['description']
		elif 'technology' in item['data']:
			item['name'] = item['data']['technology']
		else:
			item['name'] = item['data']['description']
		yield item
