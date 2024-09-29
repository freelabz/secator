from secator.decorators import task
from secator.runners import Command
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
	"bucket_aws",
	"bucket_azure",
	"bucket_digitalocean",
	# "bucket_file_enum",
	"bucket_firebase",
	"bucket_gcp",
	"builtwith",
	"bypass403",
	"c99",
	"censys",
	"certspotter",
	# "chaos",
	"columbus",
	# "credshed",
	"crobat",
	"crt",
	# "dastardly",
	# "dehashed",
	"digitorus",
	"dnscommonsrv",
	"dnsdumpster",
	"dnszonetransfer",
	"emailformat",
	"ffuf",
	"ffuf_shortnames",
	# "filedownload",
	"fingerprintx",
	"fullhunt",
	"generic_ssrf",
	"git",
	# "github_codesearch",
	"github",
	# "github_org",
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
	"masscan",
	"massdns",
	"myssl",
	# "newsletters",
	"nmap",
	"nsec",
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
	"riddler",
	"robots",
	"secretsdb",
	"securitytrails",
	"shodan_dns",
	"sitedossier",
	"skymem",
	"smuggler",
	"social",
	"sslcert",
	"subdomain_hijack",
	"subdomaincenter",
	"sublist3r",
	"telerik",
	"threatminer",
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

def output_discriminator(self, item):
	map_types = {
		'IP_ADDRESS': Ip,
		'PROTOCOL': Port,
		'OPEN_TCP_PORT': Port,
		'URL': Url,
		'TECHNOLOGY': Tag,
		# 'DNS_NAME': Record,
		'VULNERABILITY': Vulnerability,
		'FINDING': Tag
	}
	type_ = item.get('type')
	if not type_ in map_types:
		self._print(f'Found unsupported bbot type: {type_}', 'bold orange3')
		return None
	return map_types[item['type']]


@task()
class bbot(Command):
	cmd = f'bbot -y --allow-deadly'
	json_flag = '-om json'
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
		},
		Tag: {
			'name': lambda x: x['data'].get('technology') or x['data']['description'],
			'match': lambda x: x['data']['url'],
			'extra_data': lambda x: {'host': x['data']['host']},
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
			'host': lambda x: x['data']['host'] if isinstance(x['data'], dict) else x['data'],
			'extra_data': lambda x: {},
		},
		# Vulnerability: {
		# 	'name':
		# 	'provider':
		# 	'id':
		# 	'matched_at':
		# 	'ip':
		# 	'confidence':
		# 	'severity':
		# 	'cvss_score':
		# 	'tags':
		# 	'extra_data':
		# 	'description':
		# 	'references':
		# 	'reference':
		# 	'confidence_nb':
		# 	'severity_nb':
		# }
	}

	# @staticmethod
	# def item_loader(self, line):
	# 	import json
	# 	item = json.loads(line)
	# 	print(item)
	# 	return item

# ASN
# AZURE_TENANT
# DNS_NAME
# FINDING
# FINDING
# IP_ADDRESS
# OPEN_TCP_PORT
# ORG_STUB
# SCAN
# TECHNOLOGY
# URL
