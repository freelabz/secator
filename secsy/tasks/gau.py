from secsy.definitions import (DELAY, DEPTH, FOLLOW_REDIRECT, HEADER,
							   MATCH_CODES, METHOD, OPT_NOT_SUPPORTED,
							   OPT_PIPE_INPUT, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT)
from secsy.tasks._categories import HTTPCommand


class gau(HTTPCommand):
	"""Fetches known URLs from AlienVault's Open Threat Exchange, the Wayback
	Machine, Common Crawl, and URLScan.
	"""
	cmd = 'gau'
	file_flag = OPT_PIPE_INPUT
	json_flag = '--json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		DEPTH: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		MATCH_CODES: 'mc',
		METHOD: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: 'retries',
		THREADS: 'threads',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,
	}
	install_cmd = 'go install -v github.com/lc/gau/v2/cmd/gau@latest'

	# @staticmethod
	# def validate_item(self, item):
	# 	return item['url'] == 'response'
