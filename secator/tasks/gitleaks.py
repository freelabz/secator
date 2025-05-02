import click
import os
import yaml

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, PATH, GIT_REPOSITORY)
from secator.utils import caml_to_snake
from secator.output_types import Tag, Info, Error


@task()
class gitleaks(Command):
	"""Tool for detecting secrets like passwords, API keys, and tokens in git repos, files, and stdin."""
	cmd = 'gitleaks'
	tags = ['secret', 'scan']
	input_types = [PATH, GIT_REPOSITORY]
	input_flag = None
	json_flag = '-f json'
	opt_prefix = '--'
	opts = {
		'ignore_path': {'type': str, 'help': 'Path to .gitleaksignore file or folder containing one'},
		'mode': {'type': click.Choice(['git', 'dir']), 'default': 'dir', 'help': 'Gitleaks mode', 'internal': True, 'display': True},  # noqa: E501
		'config': {'type': str, 'short': 'config', 'help': 'Gitleaks config file path'}
	}
	opt_key_map = {
		"ignore_path": "gitleaks-ignore-path"
	}
	input_type = "folder"
	output_types = [Tag]
	output_map = {
		Tag: {
			'name': 'RuleID',
			'match': lambda x: f'{x["File"]}:{x["StartLine"]}:{x["StartColumn"]}',
			'extra_data': lambda x: {caml_to_snake(k): v for k, v in x.items() if k not in ['RuleID', 'File']}
		}
	}
	install_pre = {'*': ['git', 'make']}
	install_version = 'v8.24.3'
	install_cmd = (
		f'git clone https://github.com/gitleaks/gitleaks.git {CONFIG.dirs.share}/gitleaks_[install_version] || true &&'
		f'cd {CONFIG.dirs.share}/gitleaks_[install_version] && make build &&'
		f'mv {CONFIG.dirs.share}/gitleaks_[install_version]/gitleaks {CONFIG.dirs.bin}'
	)
	install_github_handle = 'gitleaks/gitleaks'

	@staticmethod
	def on_cmd(self):
		# replace fake -mode opt by subcommand
		mode = self.get_opt_value('mode')
		self.cmd = self.cmd.replace(f'{gitleaks.cmd} ', f'{gitleaks.cmd} {mode} ')

		# add output path
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd += f' -r {self.output_path}'
		self.cmd += ' --exit-code 0'

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = yaml.safe_load(f.read())
		for result in results:
			yield Tag(
				name=result['RuleID'],
				match='{File}:{StartLine}:{StartColumn}'.format(**result),
				extra_data={
					caml_to_snake(k): v for k, v in result.items()
					if k not in ['RuleID', 'File']
				}
			)
