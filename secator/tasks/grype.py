import os
import yaml

from secator.decorators import task
from secator.definitions import (DELAY, FOLLOW_REDIRECT, HEADER,
							   OPT_NOT_SUPPORTED, PROXY, RATE_LIMIT, RETRIES,
							   THREADS, TIMEOUT, USER_AGENT)
from secator.output_types import Vulnerability
from secator.tasks._categories import VulnCode
from secator.definitions import (OUTPUT_PATH)


@task()
class grype(VulnCode):
	"""Vulnerability scanner for container images and filesystems."""
	cmd = 'grype --quiet'
	input_flag = ''
	file_flag = OPT_NOT_SUPPORTED
	json_flag = '-o json'
	opt_prefix = '--'
	opt_key_map = {
		HEADER: OPT_NOT_SUPPORTED,
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
		PROXY: OPT_NOT_SUPPORTED,
		RATE_LIMIT: OPT_NOT_SUPPORTED,
		RETRIES: OPT_NOT_SUPPORTED,
		THREADS: OPT_NOT_SUPPORTED,
		TIMEOUT: OPT_NOT_SUPPORTED,
		USER_AGENT: OPT_NOT_SUPPORTED
	}
	output_types = [Vulnerability]
	item_loaders = []
	install_cmd = (
		'$(curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin) || exit 1'
	)
	install_github_handle = 'anchore/grype'

	output_map = {
        Vulnerability: {
            'name': lambda x: x['vulnerability']['id'],
			'severity': lambda x: x['vulnerability']['severity'].lower(),
			'cvss_score': lambda x: x['vulnerability']['cvss_score'],
			'references': lambda x: x['vulnerability']['urls'],
			'description': lambda x: x['vulnerability']['description']
        }
    }

	@staticmethod
	def on_cmd(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = f'{self.cmd} --file {self.output_path}'

	
	def yielder(self):
		prev = self.print_item_count
		self.print_item_count = False
		list(super().yielder())
		if self.return_code != 0:
			return
		self.results = []
		if not self.output_json:
			return
		note = f'Trivy JSON result saved to {self.output_path}'
		if self.print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				results = yaml.safe_load(f.read())
			for item in results['matches']:
				for i in item['relatedVulnerabilities'][0]['cvss']:
					item['vulnerability']['cvss_score'] = str(i['metrics']['baseScore'])
				# severity Negligible to unknow
				if item['vulnerability']['severity'] == 'Negligible':
					item['vulnerability']['severity'] = 'unknown'

				item = self._process_item(item)
				if not item:
					continue
				yield item
		self.print_item_count = prev

