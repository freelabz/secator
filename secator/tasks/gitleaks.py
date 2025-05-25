import click
import yaml

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, PATH)
from secator.utils import caml_to_snake
from secator.output_types import Tag
from secator.serializers import FileSerializer


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
		'mode': {'type': click.Choice(['git', 'dir']), 'default': 'dir', 'help': 'Gitleaks mode', 'internal': True, 'display': True},  # noqa: E501
		'config': {'type': str, 'short': 'config', 'help': 'Gitleaks config file path'}
	}
	opt_key_map = {
		"ignore_path": "gitleaks-ignore-path"
	}
	input_type = "folder"
	output_types = [Tag]
	item_loaders = [FileSerializer(output_flag='-r')]
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
		mode = self.get_opt_value('mode')
		self.cmd = self.cmd.replace(f'{gitleaks.cmd} ', f'{gitleaks.cmd} {mode} ')
		self.cmd += ' --exit-code 0'

	@staticmethod
	def on_file_loaded(self, content):
		results = yaml.safe_load(content)
		for result in results:
			yield Tag(
				name=result['RuleID'],
				match='{File}:{StartLine}:{StartColumn}'.format(**result),
				extra_data={
					caml_to_snake(k): v for k, v in result.items()
					if k not in ['RuleID', 'File']
				}
			)
