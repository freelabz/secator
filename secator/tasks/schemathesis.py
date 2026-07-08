import os
import shlex

from urllib.parse import urlparse

import xmltodict

from secator.decorators import task
from secator.definitions import HEADER, OUTPUT_PATH, RATE_LIMIT, THREADS, URL
from secator.output_types import Error, Info, Vulnerability
from secator.runners import Command
from secator.tasks._categories import OPTS


@task()
class schemathesis(Command):
	"""Property-based API fuzzer driven by an OpenAPI/GraphQL schema.

	Generates positive and negative test cases from the schema and checks every documented operation for server
	errors (5xx) and schema / content-type / header conformance violations across all HTTP methods — the negative
	fuzzing and schema-conformance testing that a template-based scanner like nuclei does not perform.
	"""
	cmd = 'schemathesis run'
	input_types = [URL]
	output_types = [Vulnerability]
	tags = ['api', 'fuzz', 'vuln']
	input_flag = None  # schema URL is a positional argument
	input_chunk_size = 1
	file_flag = None
	json_flag = None
	version_flag = '--version'
	ignore_return_code = True  # a non-zero exit code means findings were reported, not a runtime error
	encoding = 'ansi'
	opt_prefix = '--'  # schemathesis (click) uses double-dash long flags
	item_loaders = []
	meta_opts = {
		HEADER: OPTS[HEADER],
		RATE_LIMIT: OPTS[RATE_LIMIT],
		THREADS: OPTS[THREADS],
	}
	opts = {
		'base_url': {'type': str, 'short': 'burl', 'help': 'Base URL of the API under test (default: schema URL origin)'},  # noqa: E501
		'max_examples': {'type': int, 'short': 'n', 'help': 'Max generated test cases per API operation'},
		'mode': {'type': str, 'short': 'm', 'default': 'all', 'help': 'Data generation mode (positive, negative, all)'},
		'checks': {'type': str, 'short': 'c', 'default': 'all', 'help': 'Checks to run (comma-separated, or "all")'},
		'output_path': {'type': str, 'default': None, 'internal': True, 'display': False, 'help': 'JUnit XML output path'},  # noqa: E501
	}
	opt_key_map = {
		HEADER: 'header',
		RATE_LIMIT: 'rate-limit',
		THREADS: 'workers',
		'base_url': 'url',
		'max_examples': 'max-examples',
		'mode': 'mode',
		'checks': 'checks',
	}
	install_cmd = 'pipx install schemathesis'
	install_github_bin = False
	proxychains = False
	proxy_socks5 = False
	proxy_http = True

	def _base_url(self):
		base_url = self.get_opt_value('base_url')
		if not base_url and self.inputs:
			parsed = urlparse(self.inputs[0])
			base_url = f'{parsed.scheme}://{parsed.netloc}'
		return base_url or ''

	@staticmethod
	def on_cmd(self):
		# Default the base URL to the schema URL origin if not explicitly provided.
		if not self.get_opt_value('base_url'):
			base_url = self._base_url()
			if base_url:
				self.cmd += f' --url {shlex.quote(base_url)}'
		# Write results to a JUnit XML report we can parse.
		self.output_path = self.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{self.reports_folder}/.outputs/{self.fqn}.xml'
		self.cmd += f' --report junit --report-junit-path {shlex.quote(self.output_path)}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JUnit results in {self.output_path}')
			return
		yield Info(message=f'JUnit results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			data = xmltodict.parse(f.read())

		# Normalize to a list of <testsuite> elements
		root = data.get('testsuites') or data
		suites = root.get('testsuite') if isinstance(root, dict) else root
		suites = suites if isinstance(suites, list) else [suites]

		base_url = self._base_url()
		for suite in suites:
			if not suite:
				continue
			cases = suite.get('testcase', [])
			cases = cases if isinstance(cases, list) else [cases]
			for case in cases:
				failures = case.get('failure')
				if not failures:
					continue
				failures = failures if isinstance(failures, list) else [failures]
				name = case.get('@name', '').strip()
				method, _, path = name.partition(' ')
				matched_at = f'{base_url}{path}' if path.startswith('/') else (base_url or name)
				for failure in failures:
					message = failure.get('@message', '') if isinstance(failure, dict) else str(failure)
					yield Vulnerability(
						name=f'API schema fuzzing failure: {name}' if name else 'API schema fuzzing failure',
						provider='schemathesis',
						matched_at=matched_at,
						confidence='high',
						severity='medium',
						description=(message or '').strip()[:2000],
						extra_data={'operation': name, 'method': method},
						tags=['api', 'fuzz'],
					)
