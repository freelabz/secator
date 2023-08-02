#!/usr/bin/python

import os

from pkg_resources import get_distribution
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(usecwd=True), override=True)

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

# Celery local fs folders
CONFIG_FOLDER = os.environ.get('SECATOR_CONFIG_FOLDER', f'{os.path.expanduser("~")}/.secator')
TEMP_FOLDER = os.environ.get('SECATOR_TEMP_FOLDER', '/tmp')
CELERY_DATA_FOLDER = f'{TEMP_FOLDER}/celery/data'
CELERY_RESULTS_FOLDER = f'{TEMP_FOLDER}/celery/results'
PAYLOADS_FOLDER = f'{TEMP_FOLDER}/payloads'
REPORTS_FOLDER = os.environ.get('SECATOR_REPORTS_FOLDER', f'{CONFIG_FOLDER}/reports')
ROOT_FOLDER = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SCRIPTS_FOLDER = f'{ROOT_FOLDER}/scripts'
REVSHELLS_FOLDER = f'{TEMP_FOLDER}/revshells'
os.makedirs(TEMP_FOLDER, exist_ok=True)
os.makedirs(CELERY_DATA_FOLDER, exist_ok=True)
os.makedirs(CELERY_RESULTS_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)
os.makedirs(PAYLOADS_FOLDER, exist_ok=True)
os.makedirs(CONFIG_FOLDER, exist_ok=True)

# Environment variables
RECORD = bool(int(os.environ.get('RECORD', '0')))
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'filesystem://')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', f'file://{CELERY_RESULTS_FOLDER}')
DEBUG = int(os.environ.get('DEBUG', '0'))
CVES_FOLDER = f'{TEMP_FOLDER}/cves'
GOOGLE_DRIVE_PARENT_FOLDER_ID = os.environ.get('GOOGLE_DRIVE_PARENT_FOLDER_ID')
GOOGLE_CREDENTIALS_PATH = os.environ.get('GOOGLE_CREDENTIALS_PATH')
DATABASE_URI = os.environ.get('DATABASE_URI', 'mongo://localhost')
DEFAULT_SOCKS5_PROXY = os.environ.get('SOCKS5_PROXY', "socks5://127.0.0.1:9050")
DEFAULT_HTTP_PROXY = os.environ.get('HTTP_PROXY', "https://127.0.0.1:9080")

# Defaults
DEFAULT_HTTPX_FLAGS = os.environ.get('DEFAULT_HTTPX_FLAGS', '-silent -td -asn -cdn')
DEFAULT_STDIN_TIMEOUT = 1000  # seconds
DEFAULT_PROXY_TIMEOUT = 1  # seconds
DEFAULT_PROXYCHAINS_COMMAND = "proxychains"

# Constants
DEFAULT_WORDLIST = '/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt'
OPT_NOT_SUPPORTED = -1
OPT_PIPE_INPUT = -1

# Vocab
ALIVE = 'alive'
AUTO_CALIBRATION = 'auto_calibration'
COOKIES = 'cookies'
CONTENT_TYPE = 'content_type'
CONTENT_LENGTH = 'content_length'
CIDR_RANGE = 'cidr_range'
CPES = 'cpes'
DELAY = 'delay'
DOMAIN = 'domain'
DEPTH = 'depth'
EXTRA_DATA = 'extra_data'
FAILED_HTTP_STATUS = -1
FILTER_CODES = 'filter_codes'
FILTER_WORDS = 'filter_words'
FOLLOW_REDIRECT = 'follow_redirect'
PATH = 'path'
FILTER_REGEX = 'filter_regex'
FILTER_SIZE = 'filter_size'
HEADER = 'header'
HOST = 'host'
INPUT = 'input'
IP = 'ip'
JSON = 'json'
LIMIT = 'limit'
LINES = 'lines'
METHOD = 'method'
MATCH_CODES = 'match_codes'
MATCH_REGEX = 'match_regex'
MATCH_SIZE = 'match_size'
MATCH_WORDS = 'match_words'
OUTPUT_PATH = 'output_path'
PROBE = 'probe'
PORTS = 'ports'
PORT = 'port'
PROXY = 'proxy'
QUIET = 'quiet'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
SCREENSHOT = 'screenshot'
TAGS = 'tags'
THREADS = 'threads'
TIME = 'time'
TIMEOUT = 'timeout'
TOP_PORTS = 'top_ports'
URL = 'url'
USER_AGENT = 'user_agent'
USERNAME = 'username'
SCRIPT = 'script'
SERVICE_NAME = 'service_name'
SOURCES = 'sources'
STATUS_CODE = 'status_code'
SUBDOMAIN = 'subdomain'
TECH = 'tech'
TITLE = 'title'
SITE_NAME = 'site_name'
SERVICE_NAME = 'service_name'
VULN = 'vulnerability'
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
VULN_TYPE = 'type'
WEBSERVER = 'webserver'
WORDLIST = 'wordlist'
WORDS = 'words'
