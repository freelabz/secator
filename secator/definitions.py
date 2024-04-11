#!/usr/bin/python

import os
import requests

from dotenv import find_dotenv, load_dotenv
from pkg_resources import get_distribution

from secator.rich import console

load_dotenv(find_dotenv(usecwd=True), override=False)

# Globals
VERSION = get_distribution('secator').version
ASCII = f"""
			 __            
   ________  _________ _/ /_____  _____
  / ___/ _ \/ ___/ __ `/ __/ __ \/ ___/
 (__  /  __/ /__/ /_/ / /_/ /_/ / /    
/____/\___/\___/\__,_/\__/\____/_/     v{VERSION}

			freelabz.com
"""  # noqa: W605,W291

# Secator folders
ROOT_FOLDER = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LIB_FOLDER = ROOT_FOLDER + '/secator'
CONFIGS_FOLDER = LIB_FOLDER + '/configs'
EXTRA_CONFIGS_FOLDER = os.environ.get('SECATOR_EXTRA_CONFIGS_FOLDER')
BIN_FOLDER = os.environ.get('SECATOR_BIN_FOLDER', f'{os.path.expanduser("~")}/.local/bin')
DATA_FOLDER = os.environ.get('SECATOR_DATA_FOLDER', f'{os.path.expanduser("~")}/.secator')
REPORTS_FOLDER = os.environ.get('SECATOR_REPORTS_FOLDER', f'{DATA_FOLDER}/reports')
WORDLISTS_FOLDER = os.environ.get('SECATOR_WORDLISTS_FOLDER', f'{DATA_FOLDER}/wordlists')
SCRIPTS_FOLDER = f'{ROOT_FOLDER}/scripts'
CVES_FOLDER = f'{DATA_FOLDER}/cves'
PAYLOADS_FOLDER = f'{DATA_FOLDER}/payloads'
REVSHELLS_FOLDER = f'{DATA_FOLDER}/revshells'
TESTS_FOLDER = f'{ROOT_FOLDER}/tests'

# Celery local fs folders
CELERY_DATA_FOLDER = f'{DATA_FOLDER}/celery/data'
CELERY_RESULTS_FOLDER = f'{DATA_FOLDER}/celery/results'

# Environment variables
DEBUG = int(os.environ.get('DEBUG', '0'))
DEBUG_COMPONENT = os.environ.get('DEBUG_COMPONENT', '').split(',')
RECORD = bool(int(os.environ.get('RECORD', 0)))
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'filesystem://')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', f'file://{CELERY_RESULTS_FOLDER}')
CELERY_BROKER_POOL_LIMIT = int(os.environ.get('CELERY_BROKER_POOL_LIMIT', 10))
CELERY_BROKER_CONNECTION_TIMEOUT = float(os.environ.get('CELERY_BROKER_CONNECTION_TIMEOUT', 4.0))
CELERY_BROKER_VISIBILITY_TIMEOUT = int(os.environ.get('CELERY_BROKER_VISIBILITY_TIMEOUT', 3600))
CELERY_OVERRIDE_DEFAULT_LOGGING = bool(int(os.environ.get('CELERY_OVERRIDE_DEFAULT_LOGGING', 1)))
GOOGLE_DRIVE_PARENT_FOLDER_ID = os.environ.get('GOOGLE_DRIVE_PARENT_FOLDER_ID')
GOOGLE_CREDENTIALS_PATH = os.environ.get('GOOGLE_CREDENTIALS_PATH')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')

# Defaults HTTP and Proxy settings
DEFAULT_SOCKS5_PROXY = os.environ.get('SOCKS5_PROXY', "socks5://127.0.0.1:9050")
DEFAULT_HTTP_PROXY = os.environ.get('HTTP_PROXY', "https://127.0.0.1:9080")
DEFAULT_STORE_HTTP_RESPONSES = bool(int(os.environ.get('DEFAULT_STORE_HTTP_RESPONSES', 1)))
DEFAULT_PROXYCHAINS_COMMAND = "proxychains"
DEFAULT_FREEPROXY_TIMEOUT = 1  # seconds

# Default worker settings
DEFAULT_INPUT_CHUNK_SIZE = int(os.environ.get('DEFAULT_INPUT_CHUNK_SIZE', 1000))
DEFAULT_STDIN_TIMEOUT = 1000  # seconds

# Default tasks settings
DEFAULT_HTTPX_FLAGS = os.environ.get('DEFAULT_HTTPX_FLAGS', '-td')
DEFAULT_KATANA_FLAGS = os.environ.get('DEFAULT_KATANA_FLAGS', '-jc -js-crawl -known-files all -or -ob')
DEFAULT_NUCLEI_FLAGS = os.environ.get('DEFAULT_NUCLEI_FLAGS', '-stats -sj -si 20 -hm -or')
DEFAULT_FEROXBUSTER_FLAGS = os.environ.get('DEFAULT_FEROXBUSTER_FLAGS', '--auto-bail --no-state')
DEFAULT_PROGRESS_UPDATE_FREQUENCY = int(os.environ.get('DEFAULT_PROGRESS_UPDATE_FREQUENCY', 60))
DEFAULT_SKIP_CVE_SEARCH = bool(int(os.environ.get('DEFAULT_SKIP_CVE_SEARCH', 0)))

# Default wordlists
DEFAULT_HTTP_WORDLIST = os.environ.get('DEFAULT_HTTP_WORDLIST', f'{WORDLISTS_FOLDER}/fuzz-Bo0oM.txt')
DEFAULT_HTTP_WORDLIST_URL = 'https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt'
DEFAULT_DNS_WORDLIST = os.environ.get('DEFAULT_DNS_WORDLIST', f'{WORDLISTS_FOLDER}/combined_subdomains.txt')
DEFAULT_DNS_WORDLIST_URL = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt'  # noqa: E501

# Constants
OPT_NOT_SUPPORTED = -1
OPT_PIPE_INPUT = -1

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


# Create all folders
for folder in [BIN_FOLDER, DATA_FOLDER, REPORTS_FOLDER, WORDLISTS_FOLDER, SCRIPTS_FOLDER, CVES_FOLDER, PAYLOADS_FOLDER,
			   REVSHELLS_FOLDER, CELERY_DATA_FOLDER, CELERY_RESULTS_FOLDER]:
	if not os.path.exists(folder):
		console.print(f'[bold turquoise4]Creating folder {folder} ...[/] ', end='')
		os.makedirs(folder)
		console.print('[bold green]ok.[/]')


# Download default wordlists
for wordlist in ['HTTP', 'DNS']:
	wordlist_path = globals()[f'DEFAULT_{wordlist}_WORDLIST']
	wordlist_url = globals()[f'DEFAULT_{wordlist}_WORDLIST_URL']
	if not os.path.exists(wordlist_path):
		try:
			console.print(f'[bold turquoise4]Downloading default {wordlist} wordlist {wordlist_path} ...[/] ', end='')
			resp = requests.get(wordlist_url)
			with open(wordlist_path, 'w') as f:
				f.write(resp.text)
			console.print('[bold green]ok.[/]')
		except requests.exceptions.RequestException as e:
			console.print(f'[bold green]failed ({type(e).__name__}).[/]')
			pass

ADDONS_ENABLED = {}

# Check worker addon
try:
	import eventlet  # noqa: F401
	ADDONS_ENABLED['worker'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['worker'] = False

# Check google addon
try:
	import gspread  # noqa: F401
	ADDONS_ENABLED['google'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['google'] = False

# Check mongodb addon
try:
	import pymongo  # noqa: F401
	ADDONS_ENABLED['mongodb'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['mongodb'] = False

# Check redis addon
try:
	import redis  # noqa: F401
	ADDONS_ENABLED['redis'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['redis'] = False

# Check dev addon
try:
	import flake8  # noqa: F401
	ADDONS_ENABLED['dev'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['dev'] = False

# Check build addon
try:
	import hatch  # noqa: F401
	ADDONS_ENABLED['build'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['build'] = False

# Check trace addon
try:
	import memray  # noqa: F401
	ADDONS_ENABLED['trace'] = True
except ModuleNotFoundError:
	ADDONS_ENABLED['trace'] = False

# Check dev package
if os.path.exists(f'{ROOT_FOLDER}/pyproject.toml'):
	DEV_PACKAGE = True
else:
	DEV_PACKAGE = False
