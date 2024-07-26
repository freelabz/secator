from secator.decorators import task
from secator.runners import Command
from secator.output_types import Vulnerability, Port, Url, Record, Ip, Tag


BBOT_MODULES = [
	"affiliates",
	"ajaxpro",
	"anubisdb",
	"asn",
	"azure_realm",
	"azure_tenant",
	"badsecrets",
	"bevigil",
	"binaryedge",
	"bucket_amazon",
	"bucket_azure",
	"bucket_digitalocean",
	"bucket_file_enum",
	"bucket_firebase",
	"bucket_google",
	"builtwith",
	"bypass403",
	"c99",
	"censys",
	"certspotter",
	"chaos",
	"columbus",
	"credshed",
	"crobat",
	"crt",
	"dastardly",
	"dehashed",
	"digitorus",
	"dnscommonsrv",
	"dnsdumpster",
	"dnszonetransfer",
	"emailformat",
	"ffuf",
	"ffuf_shortnames",
	"filedownload",
	"fingerprintx",
	"fullhunt",
	"generic_ssrf",
	"git",
	"github_codesearch",
	"github_org",
	"gowitness",
	"hackertarget",
	"host_header",
	"httpx",
	"hunt",
	"hunterio",
	"iis_shortnames",
	"internetdb",
	"ip2location",
	"ipneighbor",
	"ipstack",
	"leakix",
	"masscan",
	"massdns",
	"myssl",
	"newsletters",
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
	"postman",
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
	"wafw00f",
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
		'Technology': Tag
	}
	type_ = item['type']
	if not type_ in map_types:
		print(f'Found unsupported type {type_}')
		return None
	return map_types[item['type']]


@task()
class bbot(Command):
	cmd = f'bbot -y -m {BBOT_MODULES_STR} --allow-deadly'
	json_flag = '-om json'
	input_flag = '-t'
	file_flag = None
	output_types = [Vulnerability, Port, Url, Record, Ip]
	output_discriminator = output_discriminator
	output_map = {
		Ip: {
			'ip': lambda x: x['data'],
			'host': lambda x: x['data'],
			'alive': lambda x: True,
		},
		Tag: {
			'name': lambda x: x['data']['technology'],
			'match': lambda x: x['data']['url'],
			'extra_data': {
				'host': lambda x: x['data']['host']
			},
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
			'port': lambda x: x['data']['port'] if 'port' in x['data'] else x['data'].split(':')[-1],
			'ip': lambda x: x['resolved_hosts'][0],
			'state': lambda x: 'OPEN',
			'service_name': lambda x: x['data']['protocol'] if 'protocol' in x['data'] else '',
			'cpes': lambda x: [],
			'host': lambda x: x['resolved_hosts'][0],
			'extra_data': lambda x: {},
		}
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
