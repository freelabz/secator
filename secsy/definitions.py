#!/usr/bin/python

import os
from pkg_resources import get_distribution

# Globals
VERSION = get_distribution('secsy').version
ASCII = f"""
   ________  ____________  __
  / ___/ _ \/ ___/ ___/ / / /
 (__  /  __/ /__(__  / /_/ / 
/____/\___/\___/____/\__, /  
                    /____/     v{VERSION}

                    freelabz.com
"""

# Environment variables
TEMP_FOLDER = os.environ.get('SECSY_TEMP_FOLDER', '/tmp')
REPORTS_FOLDER = os.environ.get('REPORTS_FOLDER', '/tmp/reports')
RECORD = bool(int(os.environ.get('RECORD', '0')))
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'filesystem://')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', f'file://{TEMP_FOLDER}/celery/results')
DEBUG = bool(int(os.environ.get('DEBUG', '0')))

# Defaults
DEFAULT_CHUNK_SIZE = 100
DEFAULT_STDIN_TIMEOUT = 5 # seconds
DEFAULT_PROXY_TIMEOUT = 1 # seconds

# Constants
FFUF_DEFAULT_WORDLIST = '/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt'
OUTPUT_TYPES = ['target', 'subdomain', 'port', 'ip', 'url', 'vulnerability']
OPT_NOT_SUPPORTED = -1
OPT_PIPE_INPUT = -1

# Vocab
AUTO_CALIBRATION = 'auto_calibration'
CONTENT_TYPE = 'content_type'
CONTENT_LENGTH = 'content_length'
CIDR_RANGE = 'cidr_range'
DELAY = 'delay'
DOMAIN = 'domain'
DEPTH = 'depth'
FAILED_HTTP_STATUS = -1
FOLLOW_REDIRECT = 'follow_redirect'
HEADER = 'header'
HOST = 'host'
INPUT = 'input'
IP = 'ip'
JSON = 'json'
LINES = 'lines'
METHOD = 'method'
MATCH_CODES = 'match_codes'
OUTPUT_PATH = 'output_path'
PROBE = 'probe'
PORTS = 'ports'
PORT = 'port'
PROXY = 'proxy'
QUIET = 'quiet'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
TAGS = 'tags'
THREADS = 'threads'
TIME = 'time'
TIMEOUT = 'timeout'
TOP_PORTS = 'top_ports'
URL = 'url'
USER_ACCOUNT = 'user_account'
USER_AGENT = 'user_agent'
USERNAME = 'username'
SCRIPT = 'script'
SOURCES = 'sources'
STATUS_CODE = 'status_code'
SUBDOMAIN = 'subdomain'
VULN = 'vulnerability'
VULN_CONFIDENCE = 'confidence'
VULN_CVSS_SCORE = 'cvss_score'
VULN_DESCRIPTION = 'description'
VULN_EXTRACTED_RESULTS = 'extracted_results'
VULN_ID = 'id'
VULN_MATCHED_AT = 'matched_at'
VULN_NAME = 'name'
VULN_PROVIDER = 'provider'
VULN_REFERENCES = 'references'
VULN_SEVERITY = 'severity'
VULN_TAGS = 'tags'
VULN_TYPE = 'type'
WORDLIST = 'wordlist'
WORDS = 'words'