import click
import os
import yaml

from pathlib import Path

from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH)
from secator.utils import caml_to_snake
from secator.output_types import Tag, Info, Error


@task()
class gitleaks(Command):
	cmd = 'gitleaks --exit-code 0'
	input_flag = None
	json_flag = '-f json'
	opts = {
		'ignore_path': {'type': str},
		'mode': {'type': click.Choice(['git', 'dir']), 'default': 'dir', 'help': 'Gitleaks mode'},
		'c': {'type': str, 'short': 'config', 'help': 'Gitleaks config file path'}
	}
	opt_key_map = {
		"ignore_path": "i"
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

	install_cmd = (
		'export GITLEAKS_VERSION="8.19.3" && '
		'wget https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -O gitleaks_latest.tar.gz &&'  # noqa: E501
		f'tar -zxvf gitleaks_latest.tar.gz gitleaks && mv gitleaks {Path.home()}/.local/bin/ &&'
		'rm gitleaks_latest.tar.gz'
	)

	@staticmethod
	def on_cmd(self):
		# replace fake -mode opt by subcommand
		mode = self.get_opt_value('mode')
		self.cmd = self.cmd.replace(
			f'-mode {mode}', ''
		).replace(
			gitleaks.cmd, f'{gitleaks.cmd} {mode}'
		)

		# add output path
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd += f' -r {self.output_path}'

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
