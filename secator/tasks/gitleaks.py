import click
import yaml

from pathlib import Path

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, PATH)
from secator.utils import caml_to_snake
from secator.serializers import FileSerializer
from secator.output_types import Tag, Info, Error
from secator.rich import console

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
	opt_value_map = {
		'mode': lambda x: convert_mode(x)
	}
	input_type = "folder"
	output_types = [Tag]
	item_loaders = [FileSerializer(output_flag='-r')]
	install_version = 'v8.24.3'
	install_cmd_pre = {'*': ['git', 'make']}
	install_cmd = (
		f'git clone https://github.com/gitleaks/gitleaks.git {CONFIG.dirs.share}/gitleaks_[install_version] || true &&'
		f'cd {CONFIG.dirs.share}/gitleaks_[install_version] && make build &&'
		f'mv {CONFIG.dirs.share}/gitleaks_[install_version]/gitleaks {CONFIG.dirs.bin}'
	)
	github_handle = 'gitleaks/gitleaks'

	@staticmethod
	def on_cmd(self):
		mode = self.cmd_options.get('mode', {}).get('value')
		if mode and mode not in GITLEAKS_MODES:
			raise Exception(f'Invalid mode: {mode}')
		if not mode and len(self.inputs) > 0:
			git_path = Path(self.inputs[0]).joinpath('.git')
			if git_path.exists():
				mode = 'git'
			else:
				mode = 'dir'
			console.print(Info(message=f'Auto mode detected: {mode} for input: {self.inputs[0]}'))
		self.cmd = self.cmd.replace(f'{gitleaks.cmd} ', f'{gitleaks.cmd} {mode} ')
		self.cmd += ' --exit-code 0'

	@staticmethod
	def on_file_loaded(self, content):
		results = yaml.safe_load(content)
		for result in results:
			extra_data = {'content': result.get('Secret')}
			extra_data.update({
				caml_to_snake(k): v for k, v in result.items()
				if k not in ['RuleID', 'File', 'Secret']
			})
			yield Tag(
				category='secret',
				name=result['RuleID'].replace('-', '_'),
				match='{File}:{StartLine}:{StartColumn}'.format(**result),
				extra_data=extra_data
			)
