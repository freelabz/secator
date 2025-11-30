import json
import os
import tempfile

from secator.decorators import task
from secator.definitions import (DELAY, HOST, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY,
								 RATE_LIMIT, RETRIES, THREADS, TIMEOUT)
from secator.output_types import Domain, Info, Error
from secator.tasks._categories import ReconDns


@task()
class opensquat(ReconDns):
	"""openSquat is an opensource Intelligence (OSINT) security tool to identify cyber squatting threats."""
	cmd = 'opensquat.py'
	input_types = [HOST]
	output_types = [Domain]
	tags = ['dns', 'recon', 'squatting']
	file_flag = None
	input_flag = None
	input_chunk_size = 0
	json_flag = None
	opt_prefix = '--'
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED
	}
	opts = {
		'confidence': {'type': int, 'short': 'c', 'default': 1, 'help': 'Confidence level (0: very high, 1: high, 2: medium, 3: low, 4: very low)'},
		'period': {'type': str, 'short': 'p', 'default': 'day', 'help': 'Searchable period [day|week|month]'},
		'method': {'type': str, 'short': 'm', 'default': 'Levenshtein', 'help': 'Method to calculate similarity [Levenshtein|JaroWinkler]'},
		'dns': {'is_flag': True, 'default': False, 'help': 'Check if domain is flagged by Quad9 DNS'},
		'ct': {'is_flag': True, 'default': False, 'help': 'Search in certificate transparency'},
		'subdomains': {'is_flag': True, 'default': False, 'help': 'Search for subdomains from flagged domains'},
		'portcheck': {'is_flag': True, 'default': False, 'help': 'Verify if port 80/443 is open'},
		'phishing': {'type': str, 'default': None, 'help': 'Search known and active Phishing sites (output file path)'},
		'domains': {'type': str, 'short': 'd', 'default': None, 'help': 'Update from FILE instead of downloading new domains'},
	}
	install_cmd = 'git clone https://github.com/atenreiro/opensquat /tmp/opensquat && cd /tmp/opensquat && pip install -r requirements.txt && ln -sf /tmp/opensquat/opensquat.py /usr/local/bin/opensquat.py'
	github_handle = 'atenreiro/opensquat'
	proxychains = False
	proxy_http = False
	proxy_socks5 = False
	profile = 'io'

	@staticmethod
	def on_init(self):
		# Save original inputs before they get cleared
		original_inputs = self.inputs.copy()
		
		# Create a temporary keywords file
		# opensquat expects keywords without TLD (e.g., "google" instead of "google.com")
		fd, keywords_path = tempfile.mkstemp(suffix='.txt', prefix='opensquat_keywords_')
		with os.fdopen(fd, 'w') as f:
			for input_item in original_inputs:
				# Strip the TLD from the domain for opensquat keyword matching
				# e.g., google.com -> google, subdomain.example.com -> subdomain.example
				keyword = input_item
				if '.' in input_item:
					# Split by dot and take all parts except the last one (TLD)
					parts = input_item.split('.')
					if len(parts) > 1:
						keyword = '.'.join(parts[:-1])
				f.write(f'{keyword}\n')
		
		self.keywords_file = keywords_path
		
		# Set output file path
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			fd, output_path = tempfile.mkstemp(suffix='.json', prefix='opensquat_output_')
			os.close(fd)
		self.output_path = output_path
		
		# Build the command with keywords file and output file
		# Clear inputs to prevent automatic input handling since we handle inputs via the keywords file
		self.inputs = []
		self.cmd = f'{self.cmd} -k {keywords_path} -o {output_path} -t json'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			data = json.load(f)

		# opensquat returns a simple JSON array of domain strings
		if isinstance(data, list):
			for domain_name in data:
				if domain_name:
					yield Domain(
						domain=domain_name,
						_source=self.unique_name
					)

	@staticmethod
	def on_end(self):
		# Clean up temporary files
		if hasattr(self, 'keywords_file') and os.path.exists(self.keywords_file):
			os.remove(self.keywords_file)
		# Only remove output file if it was auto-generated (not user-specified)
		if hasattr(self, 'output_path') and self.output_path.startswith(tempfile.gettempdir()):
			if os.path.exists(self.output_path):
				os.remove(self.output_path)
