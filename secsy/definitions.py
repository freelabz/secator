#!/usr/bin/python

import os

TEMP_FOLDER = os.environ.get('SECSY_TEMP_FOLDER', '/tmp')
RECORD = bool(os.environ.get('RECORD', '0'))
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'filesystem://')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', f'file://{TEMP_FOLDER}/celery/results')
# Redis config
# CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'
# CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'

OUTPUT_TYPES = ['target', 'subdomain', 'port', 'url', 'vulnerability']

ALL = 'all'
AUTO_CALIBRATION = 'auto_calibration'
HEADER = 'header'
DELAY = 'delay'
FOLLOW_REDIRECT = 'follow_redirect'
METHOD = 'method'
MATCH_CODES = 'match_codes'
PROXY = 'proxy'
DEPTH = 'depth'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
THREADS = 'threads'
TIMEOUT = 'timeout'
USER_AGENT = 'user_agent'
WORDLIST = 'wordlist'
URL = 'url'
STATUS_CODE = 'status_code'
WORDS = 'words'
LINES = 'lines'
CONTENT_TYPE = 'content_type'
CONTENT_LENGTH = 'content_length'
METHOD = 'method'
HOST = 'host'
TIME = 'time'
FAILED_HTTP_STATUS = -1
INPUT = 'input'
PROBE = 'probe'
PORTS = 'ports'
SCRIPT = 'script'
TOP_PORTS = 'top_ports'
TAGS = 'tags'
JSON = 'json'
CLI_MODE = 'print_timestamp'
QUIET = 'quiet'
USERNAME = 'username'
PORT = 'port'
IP = 'ip'
HOST = 'host'
SUBDOMAIN = 'subdomain'
SOURCES = 'sources'
USER_ACCOUNT = 'user_account'
VULN = 'vulnerability'
VULN_ID = 'id'
VULN_PROVIDER = 'provider'
VULN_NAME = 'name'
VULN_SEVERITY = 'severity'
VULN_TYPE = 'type'
VULN_DESCRIPTION = 'description'
VULN_CONFIDENCE = 'confidence'
VULN_CVSS_SCORE = 'cvss_score'
VULN_MATCHED_AT = 'matched_at'
VULN_TAGS = 'tags'
VULN_REFERENCES = 'references'
VULN_EXTRACTED_RESULTS = 'extracted_results'

FFUF_DEFAULT_WORDLIST = '/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt'

OPT_NOT_SUPPORTED = -1
OPT_PIPE_INPUT = -1
