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
DEBUG = CONFIG.debug.level
DEBUG_COMPONENT = CONFIG.debug.component.split(',')

# Default tasks settings
DEFAULT_NUCLEI_FLAGS = os.environ.get('DEFAULT_NUCLEI_FLAGS', '-stats -sj -si 20 -hm -or')
DEFAULT_FEROXBUSTER_FLAGS = os.environ.get('DEFAULT_FEROXBUSTER_FLAGS', '--auto-bail --no-state')

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
CIDR_RANGE = 'cidr_range'
CPES = 'cpes'
CVES = 'cves'
DELAY = 'delay'
DOMAIN = 'domain'
DEPTH = 'depth'
EXTRA_DATA = 'extra_data'
EMAIL = 'email'
FILTER_CODES = 'filter_codes'
FILTER_WORDS = 'filter_words'
FOLLOW_REDIRECT = 'follow_redirect'
FILTER_REGEX = 'filter_regex'
FILTER_SIZE = 'filter_size'
HEADER = 'header'
HOST = 'host'
IP = 'ip'
PROTOCOL = 'protocol'
LINES = 'lines'
METHOD = 'method'
MATCH_CODES = 'match_codes'
MATCH_REGEX = 'match_regex'
MATCH_SIZE = 'match_size'
MATCH_WORDS = 'match_words'
OUTPUT_PATH = 'output_path'
PATH = 'path'
PERCENT = 'percent'
PORTS = 'ports'
PORT = 'port'
PROXY = 'proxy'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
TAGS = 'tags'
THREADS = 'threads'
TIME = 'time'
TIMEOUT = 'timeout'
TOP_PORTS = 'top_ports'
TYPE = 'type'
URL = 'url'
USER_AGENT = 'user_agent'
USERNAME = 'username'
STORED_RESPONSE_PATH = 'stored_response_path'
SCRIPT = 'script'
SERVICE_NAME = 'service_name'
SOURCES = 'sources'
STATE = 'state'
STATUS_CODE = 'status_code'
TECH = 'tech'
TITLE = 'title'
SITE_NAME = 'site_name'
SERVICE_NAME = 'service_name'
CONFIDENCE = 'confidence'
CVSS_SCORE = 'cvss_score'
DESCRIPTION = 'description'
ID = 'id'
MATCHED_AT = 'matched_at'
NAME = 'name'
PROVIDER = 'provider'
REFERENCE = 'reference'
REFERENCES = 'references'
SEVERITY = 'severity'
TAGS = 'tags'
WEBSERVER = 'webserver'
WORDLIST = 'wordlist'
WORDS = 'words'


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
