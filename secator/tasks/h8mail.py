import os
import json

from secator.decorators import task
from secator.definitions import EMAIL, OUTPUT_PATH
from secator.tasks._categories import OSInt
from secator.output_types import UserAccount, Info, Error


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
	opts = {
		'config': {'type': str, 'help': 'Configuration file for API keys'},
		'local_breach': {'type': str, 'short': 'lb', 'help': 'Local breach file'}
	}
	install_cmd = 'pipx install h8mail && pipx upgrade h8mail'

	@staticmethod
	def on_start(self):
		output_path = self.get_opt_value(OUTPUT_PATH)
		if not output_path:
			output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
		self.output_path = output_path
		self.cmd = self.cmd.replace('--json', f'--json {self.output_path}')

	@staticmethod
	def on_cmd_done(self):
		if not os.path.exists(self.output_path):
			yield Error(message=f'Could not find JSON results in {self.output_path}')
			return

		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			data = json.load(f)

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
