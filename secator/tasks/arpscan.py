from secator.decorators import task
from secator.definitions import CIDR_RANGE, IP, HOST
from secator.output_types import Ip, Warning, Error, Info
from secator.runners import Command


@task()
class arpscan(Command):
	"""Scan a CIDR range for alive hosts using ARP."""
	cmd = 'arp-scan --plain --resolve --format="${ip}\t${name}\t${mac}\t${vendor}"'
	input_types = [CIDR_RANGE, IP, HOST]
	output_types = [Ip]
	input_flag = None
	requires_sudo = True
	file_copy_sudo = True  # Copy the input file to /tmp since it cannot access the reports folder
	file_flag = '-f'
	version_flag = '-V'
	tags = ['ip', 'recon']
	default_inputs = ''
	opt_prefix = '--'
	opts = {
		'resolve': {'is_flag': True, 'short': 'r', 'default': False, 'help': 'Resolve IP addresses to hostnames'},
		'interface': {'type': str, 'short': 'i', 'default': None, 'help': 'Interface to use'},
		'localnet': {'is_flag': True, 'short': 'l', 'default': False, 'help': 'Scan local network'},
		'ouifile': {'type': str, 'short': 'o', 'default': None, 'help': 'Use IEEE registry vendor mapping file.'},
		'macfile': {'type': str, 'short': 'm', 'default': None, 'help': 'Use custom vendor mapping file.'},
	}
	github_handle = 'royhills/arp-scan'
	install_github_bin = False
	install_pre = {
		'*': ['arp-scan'],
	}
	install_post = {
		'*': 'sudo ln -s /usr/sbin/arp-scan /usr/local/bin/arp-scan || true'
	}

	@staticmethod
	def on_cmd(self):
		if not self.inputs:
			self.add_result(Info(message='No input passed to arpscan, scanning local network'))
			self.cmd += ' --localnet'

	@staticmethod
	def on_line(self, line):
		if 'WARNING:' in line:
			return Warning(message=line.split('WARNING:')[1].strip())
		elif 'permission' in line:
			return Error(message=line + "\n" + (
				"You must [bold]run this task as root[/bold] to scan the network, or use "
				"[green]sudo setcap cap_net_raw=eip /usr/sbin/arp-scan[/green] to grant the [bold]CAP_NET_RAW[/bold] capability "
				"to the [bold]arp-scan[/bold] binary."))
		else:
			line_parts = line.strip().split('\t')
			if len(line_parts) == 4:
				return Ip(
					ip=line_parts[0],
					host=line_parts[1],
					alive=True,
					extra_data={
						'mac': line_parts[2],
						'vendor': line_parts[3],
						'protocol': 'arp',
					},
					_source=self.unique_name
				)
		return line
