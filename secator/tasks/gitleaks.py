import click
import os
import yaml

from pathlib import Path

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, PATH)
from secator.utils import caml_to_snake
from secator.output_types import Tag, Info, Error

GITLEAKS_MODES = ['git', 'dir']


def convert_mode(mode):
	return 'dir' if mode == 'filesystem' else 'git' if mode == 'git' else mode


@task()
class gitleaks(Command):
	"""Tool for detecting secrets like passwords, API keys, and tokens in git repos, files, and stdin."""
	cmd = 'gitleaks'
	tags = ['secret', 'scan']
	input_types = [PATH]
	input_flag = None
	json_flag = '-f json'
	opt_prefix = '--'
	opts = {
		'ignore_path': {'type': str, 'help': 'Path to .gitleaksignore file or folder containing one'},
		'mode': {'type': click.Choice(GITLEAKS_MODES), 'help': f'Scan mode ({", ".join(GITLEAKS_MODES)})', 'internal': True},  # noqa: E501
		'config': {'type': str, 'short': 'config', 'help': 'Config file path'}
	}
	opt_key_map = {
		"ignore_path": "gitleaks-ignore-path"
	}
	opt_key_value = {
		'mode': lambda x: convert_mode(x)
	}
	input_type = "folder"
	output_types = [Tag]
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
		mode = self.get_opt_value('mode')
		if mode and mode not in GITLEAKS_MODES:
			raise Exception(f'Invalid mode: {mode}')
		if not mode and len(self.inputs) > 0:
			git_path = Path(self.inputs[0]).joinpath('.git')
			if git_path.exists():
				mode = 'git'
			else:
				mode = 'dir'
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
			extra_data = {'content': result.get('Secret')}
			extra_data.update({
				caml_to_snake(k): v for k, v in result.items()
				if k not in ['RuleID', 'File', 'Secret']
			})
			yield Tag(
				name=result['RuleID'].replace('-', '_'),
				category='secret',
				match='{File}:{StartLine}:{StartColumn}'.format(**result),
				extra_data=extra_data
			)
