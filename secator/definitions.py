#!/usr/bin/python

import os

from importlib.metadata import version

from secator.config import CONFIG, ROOT_FOLDER


# Globals
VERSION = version('secator')
ASCII = rf"""
			 __            
   ________  _________ _/ /_____  _____
  / ___/ _ \/ ___/ __ `/ __/ __ \/ ___/
 (__  /  __/ /__/ /_/ / /_/ /_/ / /    
/____/\___/\___/\__,_/\__/\____/_/     v{VERSION}

			freelabz.com
"""  # noqa: W605,W291

# Debug
DEBUG = CONFIG.debug.split(',')

# Constants
OPT_NOT_SUPPORTED = -1
OPT_PIPE_INPUT = -1
STATE_COLORS = {
	'PENDING': 'dim yellow3',
	'RUNNING': 'bold yellow3',
	'SUCCESS': 'bold green',
	'FAILURE': 'bold red',
	'REVOKED': 'bold magenta'
}

# Vocab
ALIVE = 'alive'
AUTO_CALIBRATION = 'auto_calibration'
CONTENT_TYPE = 'content_type'
CONTENT_LENGTH = 'content_length'
CERTIFICATE_STATUS_UNKNOWN = 'Unknown'
CERTIFICATE_STATUS_REVOKED = 'Revoked'
CERTIFICATE_STATUS_TRUSTED = 'Trusted'
CIDR_RANGE = 'cidr_range'
CONFIDENCE = 'confidence'
CPES = 'cpes'
CVES = 'cves'
CVSS_SCORE = 'cvss_score'
DATA = 'data'
DELAY = 'delay'
DESCRIPTION = 'description'
DOCKER_IMAGE = 'docker_image'
DOMAIN = 'domain'
DEPTH = 'depth'
EXTRA_DATA = 'extra_data'
EMAIL = 'email'
FILENAME = 'filename'
FILTER_CODES = 'filter_codes'
FILTER_WORDS = 'filter_words'
FOLLOW_REDIRECT = 'follow_redirect'
FILTER_REGEX = 'filter_regex'
FILTER_SIZE = 'filter_size'
GIT_REPOSITORY = 'git_repository'
HEADER = 'header'
HOST = 'host'
HOST_PORT = 'host:port'
IBAN = 'iban'
ID = 'id'
IP = 'ip'
PROTOCOL = 'protocol'
LINES = 'lines'
METHOD = 'method'
MAC_ADDRESS = 'mac'
MATCHED_AT = 'matched_at'
MATCH_CODES = 'match_codes'
MATCH_REGEX = 'match_regex'
MATCH_SIZE = 'match_size'
MATCH_WORDS = 'match_words'
NAME = 'name'
ORG_NAME = 'org_name'
OUTPUT_PATH = 'output_path'
PATH = 'path'
PERCENT = 'percent'
PORTS = 'ports'
PORT = 'port'
PROVIDER = 'provider'
PROXY = 'proxy'
RATE_LIMIT = 'rate_limit'
REFERENCE = 'reference'
REFERENCES = 'references'
RETRIES = 'retries'
SCRIPT = 'script'
SERVICE_NAME = 'service_name'
SEVERITY = 'severity'
SITE_NAME = 'site_name'
SLUG = 'slug'
SOURCES = 'sources'
STORED_RESPONSE_PATH = 'stored_response_path'
STATE = 'state'
STATUS_CODE = 'status_code'
STRING = 'str'
TAGS = 'tags'
TECH = 'tech'
TECHNOLOGY = 'technology'
THREADS = 'threads'
TIME = 'time'
TIMEOUT = 'timeout'
TITLE = 'title'
TOP_PORTS = 'top_ports'
TYPE = 'type'
URL = 'url'
USER_AGENT = 'user_agent'
USERNAME = 'username'
UUID = 'uuid'
WEBSERVER = 'webserver'
WORDLIST = 'wordlist'
WORDS = 'words'

# Allowed input types
INPUT_TYPES = [
	URL,
	IP,
	CIDR_RANGE,
	HOST,
	MAC_ADDRESS,
	EMAIL,
	IBAN,
	UUID,
	PATH,
	SLUG,
	STRING,
]


def is_importable(module_to_import):
	import importlib
	try:
		importlib.import_module(module_to_import)
		return True
	except ModuleNotFoundError:
		return False
	except Exception as e:
		print(f'Failed trying to import {module_to_import}: {str(e)}')
		return False


ADDONS_ENABLED = {}

for addon, module in [
	('worker', 'eventlet'),
	('gdrive', 'gspread'),
	('gcs', 'google.cloud.storage'),
	('mongodb', 'pymongo'),
	('redis', 'redis'),
	('dev', 'flake8'),
	('trace', 'memray'),
	('build', 'hatch')
]:
	ADDONS_ENABLED[addon] = is_importable(module)

# Check dev package
if os.path.exists(f'{ROOT_FOLDER}/pyproject.toml'):
	DEV_PACKAGE = True
else:
	DEV_PACKAGE = False
