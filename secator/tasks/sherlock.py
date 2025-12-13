import csv
import os
import shlex

from secator.decorators import task
from secator.definitions import (DELAY, EXTRA_DATA, OPT_NOT_SUPPORTED, OUTPUT_PATH, PROXY,
								 RATE_LIMIT, RETRIES, SITE_NAME, THREADS,
								 TIMEOUT, URL, STRING, SLUG, USERNAME)
from secator.output_types import UserAccount, Info, Error
from secator.tasks._categories import ReconUser


@task()
class sherlock(ReconUser):
	"""Find usernames across social networks."""
	cmd = 'sherlock'
	input_types = [SLUG, STRING, USERNAME]
	output_types = [UserAccount]
	tags = ['user', 'recon', 'username', 'osint']
	file_flag = None
	input_flag = None
	opt_prefix = '--'
	opts = {
		'site': {'type': str, 'help': 'Limit analysis to specific sites'},
		'nsfw': {'is_flag': True, 'default': False, 'help': 'Include NSFW sites in checks'},
		'print_found': {'is_flag': True, 'default': True, 'help': 'Print found sites'},
	}
	opt_key_map = {
		DELAY: OPT_NOT_SUPPORTED,
		PROXY: 'proxy',
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		TIMEOUT: 'timeout',
		THREADS: OPT_NOT_SUPPORTED,
		'print_found': '--print-found',
	}
	install_version = '0.16.0'
	install_cmd = 'pipx install sherlock-project==[install_version] --force'
	socks5_proxy = True
	profile = 'io'

	@staticmethod
	def on_start(self):
		# Sherlock creates CSV files named {username}.csv in the current directory
		# We need to set the working directory to our output folder
		self.output_folder = f'{self.reports_folder}/.outputs'
		os.makedirs(self.output_folder, exist_ok=True)
		self.cwd = self.output_folder
		# Add CSV output flag
		self.cmd += ' --csv'

	@staticmethod
	def on_cmd_done(self):
		# Sherlock creates CSV files named {username}.csv in working directory
		# Find all CSV files in the output folder
		csv_files = []
		for item in self.inputs:
			username = str(item)
			csv_path = os.path.join(self.output_folder, f'{username}.csv')
			if os.path.exists(csv_path):
				csv_files.append(csv_path)

		if not csv_files:
			yield Error(message=f'Could not find CSV results in {self.output_folder}')
			return

		for csv_path in csv_files:
			yield Info(message=f'CSV results saved to {csv_path}')
			
			with open(csv_path, 'r') as f:
				reader = csv.DictReader(f)
				for row in reader:
					# Check if the username exists (exists field is 'Claimed')
					if row.get('exists') == 'Claimed':
						yield UserAccount(
							username=row.get('username', ''),
							site_name=row.get('name', ''),
							url=row.get('url_user', ''),
							extra_data={
								'http_status': row.get('http_status', ''),
								'response_time_s': row.get('response_time_s', ''),
								'url_main': row.get('url_main', ''),
							}
						)

	@staticmethod
	def validate_item(self, item):
		if isinstance(item, dict):
			return item.get('exists') == 'Claimed'
		return True
