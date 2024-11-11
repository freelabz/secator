import click
import os
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.output_types import Vulnerability, Tag, Info, Error
from secator.definitions import (OUTPUT_PATH)


@task()
class trivy(Command):
	cmd = 'trivy'
	input_flag = None
	json_flag = '-f json'
	opts = {
		"mode": {"type": click.Choice(['image', 'fs', 'repo']), "default": "image", "help": "Trivy mode (`image`, `fs` or `repo`)"}  # noqa: E501
	}
	output_map = {
		Vulnerability: {
			'name': 'VulnerabilityID',
			'description': 'Description',
			'severity': lambda x: x['Severity'].lower(),
			'references': 'References'
		},
		Tag: {
			'name': 'RuleID',
			'match': 'Match',
			'extra_data': lambda x: {k: v for k, v in x.items() if k not in ['RuleID', 'Match']}
		}
	}
	output_types = [Tag, Vulnerability]
	install_cmd = "sudo apt install trivy"
	install_github_handle = 'aquasecurity/trivy'

	@staticmethod
	def on_cmd(self):
		mode = self.get_opt_value('mode')
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = self.cmd.replace(f' -mode {mode}', '').replace('trivy', f'trivy {mode}')
		self.cmd += f' -o {self.output_path}'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())['Results']
		for item in results:
			yield from item.get('Vulnerabilities', [])
			yield from item.get('Secrets', [])
