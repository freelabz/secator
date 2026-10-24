import csv
import os
import shlex

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import (DATA, DELAY, FOLLOW_REDIRECT, HEADER, METHOD, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY,
								 RATE_LIMIT, REQUEST, RETRIES, THREADS, TIMEOUT, URL, USER_AGENT)
from secator.output_types import Info, Url, Warning
from secator.tasks._categories import HttpBase

# EyeWitness records a request OUTCOME (browser-driven), not the raw HTTP code: "Successful" when the page loaded,
# else a connection/driver error state. Map those to the closest HTTP status code (the raw text is also kept in
# extra_data['request_status']). Unknown/driver errors -> 0.
EYEWITNESS_STATUS_CODES = {
	'Successful': 200,
	'BadStatus': 400,
	'Timeout': 504,
	'Connection Reset': 502,
	'ConnReset': 502,
	'Connection Refused': 502,
	'ConnRefuse': 502,
	'DNS Failed': 502,
	'SSL Error': 525,
	'SSLHandshake': 525,
}


@task()
class eyewitness(HttpBase):
	"""Screenshot web interfaces and categorize them (login pages, default creds, dir listings, ...)."""

	cmd = 'eyewitness'
	input_types = [URL]
	output_types = [Url]
	tags = ['screenshot', 'web', 'recon']
	input_flag = None  # EyeWitness only writes Requests.csv (parsed below) in multi mode (`-f <file>`), NOT single mode (`--single`)
	file_flag = '-f'
	file_eof_newline = True
	version_flag = OPT_NOT_SUPPORTED
	opt_prefix = '--'
	opts = {
		'prepend_https': {'is_flag': True, 'default': False, 'help': 'Try HTTPS then HTTP for hostnames without a scheme'},  # noqa: E501
	}
	opt_key_map = {
		TIMEOUT: 'timeout',
		THREADS: 'threads',
		DELAY: 'delay',
		RETRIES: 'max-retries',
		USER_AGENT: 'user-agent',
		# EyeWitness has no per-request header / follow-redirect / rate-limit / method / body, and splits proxy
		# into ip/port/type — so drop the HttpBase meta-opts it can't take.
		HEADER: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		METHOD: OPT_NOT_SUPPORTED,
		REQUEST: OPT_NOT_SUPPORTED,
		DATA: OPT_NOT_SUPPORTED,
		'prepend_https': 'prepend-https',
	}
	proxychains = False
	proxy_socks5 = False
	proxy_http = False
	profile = 'large'
	install_version = 'feat/csv-status-code'
	install_pre = {
		'*': ['chromium', 'chromium-driver', 'xvfb', 'wget', 'curl', 'jq', 'cmake', 'python3-venv', 'python3-dev'],
		'arch': ['chromium', 'xorg-server-xvfb']
	}
	install_cmd = (
		f'git clone --depth 1 --branch [install_version] https://github.com/freelabz/EyeWitness.git {CONFIG.dirs.share}/EyeWitness || true && '  # noqa: E501
		f'python3 -m venv {CONFIG.dirs.share}/EyeWitness/.venv && '
		f'{CONFIG.dirs.share}/EyeWitness/.venv/bin/pip install -q netaddr selenium rapidfuzz psutil pyvirtualdisplay && '  # noqa: E501
		f'printf \'#!/bin/sh\\nexec {CONFIG.dirs.share}/EyeWitness/.venv/bin/python {CONFIG.dirs.share}/EyeWitness/Python/EyeWitness.py "$@"\\n\' > {CONFIG.dirs.bin}/eyewitness && '  # noqa: E501
		f'chmod +x {CONFIG.dirs.bin}/eyewitness'
	)
	install_github_bin = False
	github_handle = 'freelabz/EyeWitness'

	@staticmethod
	def on_cmd(self):
		# EyeWitness writes a report DIRECTORY (report.html + Requests.csv + screens/), not stdout.
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.fqn}'
		self.output_path = output_path

		# EyeWitness only accepts --single or -f, never a positional target. For a single input secator appends it
		# as a positional, so rewrite it to a -f targets file (which also forces multi mode → Requests.csv).
		if len(self.inputs) == 1:
			targets_file = f'{self.reports_folder}/.inputs/{self.fqn}.txt'
			os.makedirs(os.path.dirname(targets_file), exist_ok=True)
			with open(targets_file, 'w') as f:
				f.write(self.inputs[0] + '\n')
			self.cmd = self.cmd.replace(f' {shlex.quote(self.inputs[0])}', f' -f {shlex.quote(targets_file)}', 1)

		self.cmd += f' --web --no-prompt -d {shlex.quote(self.output_path)}'

	@staticmethod
	def on_cmd_done(self):
		csv_path = os.path.join(self.output_path, 'Requests.csv')
		if not os.path.exists(csv_path):
			yield Warning(message=f'No results found (could not find CSV)')
			return
		yield Info(message=f'EyeWitness report saved to {self.output_path}')

		count = 0
		with open(csv_path, newline='') as f:
			reader = csv.DictReader(f)
			for row in reader:
				row = {(k or '').strip(): (v or '').strip() for k, v in row.items()}
				url = row.get('URL')
				screenshot = row.get('Screenshot Path')
				if not url or not screenshot:  # only report endpoints we actually captured
					continue
				count += 1
				title = row.get('Title') or ''
				category = row.get('Category') or ''
				default_creds = row.get('Default Creds') or ''
				raw_status = row.get('Request Status') or ''
				# Prefer the real HTTP code from the "Status Code" column (freelabz fork / PR #729). Fall back
				# to mapping the browser-outcome text when the column is absent (upstream EyeWitness) or blank
				# (a connection-level failure with no HTTP response).
				try:
					status_code = int(row.get('Status Code') or '')
				except ValueError:
					status_code = EYEWITNESS_STATUS_CODES.get(raw_status, 0)

				url_tags = ['screenshot', 'web']
				if category:
					url_tags.append(category)

				yield Url(
					url=url,
					host=row.get('Domain') or '',
					status_code=status_code,
					title=title,
					screenshot_path=screenshot,
					tags=url_tags,
					extra_data={
						'category': category or 'uncategorized',
						'default_creds': default_creds,
						'port': row.get('Port') or '',
						'request_status': raw_status,
					},
				)

		if count == 0:
			yield Warning(message='No web interfaces were captured by EyeWitness.')
