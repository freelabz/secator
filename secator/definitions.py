#!/usr/bin/python

import os
import requests

from dotenv import find_dotenv, load_dotenv
from pkg_resources import get_distribution, parse_version

load_dotenv(find_dotenv(usecwd=True), override=False)


def get_latest_version():
	"""Get latest secator version from GitHub API."""
	try:
		resp = requests.get('https://api.github.com/repos/freelabz/secator/releases/latest', timeout=2)
		resp.raise_for_status()
		latest_version = resp.json()['name'].lstrip('v')
		return latest_version
	except (requests.exceptions.RequestException):
		return None


# Globals
VERSION = get_distribution('secator').version
VERSION_LATEST = get_latest_version()
VERSION_OBSOLETE = parse_version(VERSION_LATEST) > parse_version(VERSION) if VERSION_LATEST else False
VERSION_STR = f'{VERSION} [bold red](outdated)[/]' if VERSION_OBSOLETE else VERSION

ASCII = f"""
			 __            
   ________  _________ _/ /_____  _____
  / ___/ _ \/ ___/ __ `/ __/ __ \/ ___/
 (__  /  __/ /__/ /_/ / /_/ /_/ / /    
/____/\___/\___/\__,_/\__/\____/_/     v{VERSION_STR}

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
os.makedirs(BIN_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)
os.makedirs(WORDLISTS_FOLDER, exist_ok=True)
os.makedirs(SCRIPTS_FOLDER, exist_ok=True)
os.makedirs(CVES_FOLDER, exist_ok=True)
os.makedirs(PAYLOADS_FOLDER, exist_ok=True)
os.makedirs(REVSHELLS_FOLDER, exist_ok=True)

# Celery local fs folders
CELERY_DATA_FOLDER = f'{DATA_FOLDER}/celery/data'
CELERY_RESULTS_FOLDER = f'{DATA_FOLDER}/celery/results'
os.makedirs(CELERY_DATA_FOLDER, exist_ok=True)
os.makedirs(CELERY_RESULTS_FOLDER, exist_ok=True)

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
DEFAULT_HTTP_WORDLIST = os.environ.get('DEFAULT_HTTP_WORDLIST', f'{WORDLISTS_FOLDER}/Fuzzing/fuzz-Bo0oM.txt')
DEFAULT_DNS_WORDLIST = os.environ.get('DEFAULT_DNS_WORDLIST', f'{WORDLISTS_FOLDER}/Discovery/DNS/combined_subdomains.txt')  # noqa:E501

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

# Check worker addon
try:
	import eventlet  # noqa: F401
	WORKER_ADDON_ENABLED = 1
except ModuleNotFoundError:
	WORKER_ADDON_ENABLED = 0

# Check google addon
try:
	import gspread  # noqa: F401
	GOOGLE_ADDON_ENABLED = 1
except ModuleNotFoundError:
	GOOGLE_ADDON_ENABLED = 0

# Check mongodb addon
try:
	import pymongo  # noqa: F401
	MONGODB_ADDON_ENABLED = 1
except ModuleNotFoundError:
	MONGODB_ADDON_ENABLED = 0

# Check redis addon
try:
	import redis  # noqa: F401
	REDIS_ADDON_ENABLED = 1
except ModuleNotFoundError:
	REDIS_ADDON_ENABLED = 0

# Check dev addon
try:
	import flake8  # noqa: F401
	DEV_ADDON_ENABLED = 1
except ModuleNotFoundError:
	DEV_ADDON_ENABLED = 0

# Check build addon
try:
	import hatch  # noqa: F401
	BUILD_ADDON_ENABLED = 1
except ModuleNotFoundError:
	BUILD_ADDON_ENABLED = 0

# Check trace addon
try:
	import memray  # noqa: F401
	TRACE_ADDON_ENABLED = 1
except ModuleNotFoundError:
	TRACE_ADDON_ENABLED = 0

# Check dev package
if os.path.exists(f'{ROOT_FOLDER}/pyproject.toml'):
	DEV_PACKAGE = 1
else:
	DEV_PACKAGE = 0
