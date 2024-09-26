import click
import os
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH)
from secator.utils import caml_to_snake
from secator.output_types import Tag


@task()
class gitleaks(Command):
	cmd = 'gitleaks --exit-code 0'
	input_flag = None
	json_flag = '-f json'
	opts = {
		"ignore_path": {"type": str},
		"mode": {"type": click.Choice(['git', 'dir']), "default": "dir", "help": "Gitleaks mode (`git` or `dir`)"}
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

	def yielder(self):
		prev = self.print_item_count
		self.print_item_count = False
		list(super().yielder())
		if self.return_code != 0:
			return
		self.results = []
		if not self.output_json:
			return
		note = f'gitleaks JSON results saved to {self.output_path}'
		if self.print_line:
			self._print(note)
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				results = yaml.safe_load(f.read())
			for item in results:
				item = self._process_item(item)
				if not item:
					continue
				yield item
		self.print_item_count = prev
