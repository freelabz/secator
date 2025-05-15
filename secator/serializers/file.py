import os
import re
from secator.definitions import OUTPUT_PATH
from secator.output_types import Info, Warning


class FileSerializer:

	def __init__(self, output_flag=None, output_path_regex=None):
		self.output_flag = output_flag
		self.output_path_regex = output_path_regex

	def on_cmd_start(self, runner):
		# Output path regex set
		if self.output_path_regex:
			return

		# Check if output path is set
		self.output_path = runner.get_opt_value(OUTPUT_PATH)
		if not self.output_path:
			self.output_path = f'{runner.reports_folder}/.outputs/{runner.unique_name}.json'

		# Add output flag to command
		if self.output_flag:
			if self.output_flag in runner.cmd:
				runner.cmd = runner.cmd.replace(self.output_flag, f'{self.output_flag} {self.output_path}')
			elif self.output_flag:
				runner.cmd += f' {self.output_flag} {self.output_path}'

	def on_cmd_done(self, runner):
		# Find output paths in command output using regex
		if self.output_path_regex:
			matches = re.findall(self.output_path_regex, runner.output)
			if not matches:
				runner.add_result(Warning(message=f'Could not find output file from regex {self.output_path_regex}'), print=True)
				return
			self.output_path = matches

		output_paths = self.output_path if isinstance(self.output_path, list) else [self.output_path]
		for output_path in output_paths:
			if not os.path.exists(output_path):
				runner.add_result(Warning(message=f'Could not find output file {output_path}'), print=True)
				return

			# Read the output file
			runner.add_result(Info(message=f'Output file saved to {output_path}'), print=True)
			with open(output_path, 'r') as f:
				content = f.read()
				yield content
