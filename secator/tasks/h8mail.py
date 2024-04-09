import os
import json

from secator.decorators import task
from secator.definitions import EMAIL, OUTPUT_PATH
from secator.tasks._categories import OSInt
from secator.output_types import UserAccount


@task()
class h8mail(OSInt):
	"""Email information and password lookup tool."""
	cmd = 'h8mail'
	json_flag = '--json '
	input_flag = '--targets'
	input_type = EMAIL
	file_flag = '-domain'
	version_flag = '--help'
	opt_prefix = '--'
	opt_key_map = {

	}
	opts = {
		'config': {'type': str, 'help': 'Configuration file for API keys'},
		'local_breach': {'type': str, 'short': 'lb', 'help': 'Local breach file'}
	}
	output_map = {
	}

	install_cmd = 'pipx install h8mail'

	@staticmethod
	def on_start(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = self.cmd.replace('--json', f'--json {self.output_path}')

	def yielder(self):
		prev = self.print_item_count
		self.print_item_count = False
		list(super().yielder())
		if self.return_code != 0:
			return
		self.results = []
		if os.path.exists(self.output_path):
			with open(self.output_path, 'r') as f:
				data = json.load(f)
			if self.orig:  # original h8mail output
				yield data
				return
			targets = data['targets']
			for target in targets:
				email = target['target']
				target_data = target.get('data', [])
				pwn_num = target['pwn_num']
				if not pwn_num > 0:
					continue
				if len(target_data) > 0:
					entries = target_data[0]
					for entry in entries:
						source, site_name = tuple(entry.split(':'))
						yield UserAccount(**{
							"site_name": site_name,
							"username": email.split('@')[0],
							"email": email,
							"extra_data": {
								'source': source
							},
						})
				else:
					yield UserAccount(**{
						"username": email.split('@')[0],
						"email": email,
						"extra_data": {
							'source': self.get_opt_value('local_breach')
						},
					})
		self.print_item_count = prev
