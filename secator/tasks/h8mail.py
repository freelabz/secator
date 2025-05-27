import json

from secator.decorators import task
from secator.definitions import EMAIL
from secator.tasks._categories import OSInt
from secator.output_types import UserAccount
from secator.serializers import FileSerializer


@task()
class h8mail(OSInt):
	"""Email information and password lookup tool."""
	cmd = 'h8mail'
	input_types = [EMAIL]
	output_types = [UserAccount]
	tags = ['user', 'recon', 'email']
	json_flag = '--json '
	input_flag = '--targets'
	item_loaders = [FileSerializer(output_flag='--json')]
	file_flag = '-domain'
	version_flag = '--help'
	opt_prefix = '--'
	opts = {
		'config': {'type': str, 'help': 'Configuration file for API keys'},
		'local_breach': {'type': str, 'short': 'lb', 'help': 'Local breach file'}
	}
	install_version = '2.5.6'
	install_cmd = 'pipx install h8mail==[install_version] --force'

	@staticmethod
	def on_file_loaded(self, content):
		data = json.loads(content)
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
