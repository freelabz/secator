from secsy.cmd import CommandRunner
from secsy.definitions import *


class HTTPCommand(CommandRunner):
	meta_opts = {
		HEADER: {'type': str, 'help': 'Custom header to add to each request in the form "KEY1:VALUE1; KEY2:VALUE2"'},
		DELAY: {'type': float, 'help': 'Delay to add between each requests'},
		DEPTH: {'type': int, 'help': 'Scan / crawl depth'},
		FOLLOW_REDIRECT: {'is_flag': True, 'default': True, 'help': 'Follow HTTP redirects'},
		MATCH_CODES: {'type': str, 'default': '200,204,301,302,307,401,405', 'help': 'Match HTTP status codes e.g "201,300,301"'},
		METHOD: {'type': str, 'help': 'HTTP method to use for requests'},
		PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
		RATE_LIMIT: {'type':  int, 'help': 'Rate limit, i.e max number of requests per second'},
		RETRIES: {'type': int, 'help': 'Retries'},
		THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
		TIMEOUT: {'type': int, 'help': 'Request timeout'},
		USER_AGENT: {'type': str, 'help': 'User agent, e.g "Mozilla Firefox 1.0"'},
	}
	input_type = URL
	output_field = URL
	output_type = URL
	output_schema = [
		URL,
		METHOD,
		STATUS_CODE,
		WORDS, LINES,
		CONTENT_TYPE,
		CONTENT_LENGTH,
		HOST,
		TIME
	]
	output_table_fields = [
		URL,
		STATUS_CODE,
		CONTENT_TYPE,
		TIME
	]


class ReconCommand(CommandRunner):
	meta_opts = {
		DELAY: {'type': float, 'help': 'Delay to add between each requests'},
		PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
		RATE_LIMIT: {'type':  int, 'help': 'Rate limit, i.e max number of requests per second'},
		RETRIES: {'type': int, 'help': 'Retries'},
		THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
		TIMEOUT: {'type': int, 'help': 'Request timeout'},
	}
	input_type = HOST


class VulnCommand(CommandRunner):
	meta_opts = {
		HEADER: {'type': str, 'help': 'Custom header to add to each request in the form "KEY1:VALUE1; KEY2:VALUE2"'},
		DELAY: {'type': float, 'help': 'Delay to add between each requests'},
		FOLLOW_REDIRECT: {'is_flag': True, 'default': True, 'help': 'Follow HTTP redirects'},
		PROXY: {'type': str, 'help': 'HTTP(s) proxy'},
		RATE_LIMIT: {'type':  int, 'help': 'Rate limit, i.e max number of requests per second'},
		RETRIES: {'type': int, 'help': 'Retries'},
		THREADS: {'type': int, 'help': 'Number of threads to run', 'default': 50},
		TIMEOUT: {'type': int, 'help': 'Request timeout'},
		USER_AGENT: {'type': str, 'help': 'User agent, e.g "Mozilla Firefox 1.0"'}
	}
	output_schema = [
		VULN_ID,
		VULN_PROVIDER,
		VULN_NAME,
		VULN_DESCRIPTION,
		VULN_SEVERITY,
		VULN_CONFIDENCE,
		VULN_CVSS_SCORE,
		VULN_MATCHED_AT,
		VULN_TAGS,
		VULN_REFERENCES,
		VULN_EXTRACTED_RESULTS,
	]
	output_table_fields = [
		VULN_MATCHED_AT,
		VULN_SEVERITY,
		VULN_CONFIDENCE,
		VULN_NAME,
		VULN_ID,
		VULN_CVSS_SCORE,
		VULN_TAGS,
		VULN_EXTRACTED_RESULTS
	]
	output_table_sort_fields = ('_confidence', '_severity', 'matched_at', 'cvss_score')
	output_type = VULN
	input_type = HOST

	@staticmethod
	def on_item_converted(self, item):
		severity_map = {
			'critical': 0,
			'high': 1,
			'medium': 2,
			'low': 3,
			'info': 4,
			None: 5
		}
		item['_severity'] = severity_map[item['severity']]
		item['_confidence'] = severity_map[item['confidence']]
		return item