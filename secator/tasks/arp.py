import re
import validators

from secator.decorators import task
from secator.output_types import Ip
from secator.runners import Command


@task()
class arp(Command):
	"""Display the system ARP cache."""
	cmd = 'arp -a'
	output_types = [Ip]
	input_flag = None
	default_inputs = ''
	requires_sudo = True
	tags = ['ip', 'recon']
	opts = {}
	install_pre = {
		'*': ['net-tools'],
	}

	@staticmethod
	def item_loader(self, line):
		# Parse ARP output format:
		# ? (172.18.0.4) at 02:42:ac:12:00:04 [ether] on br-781c859806d7
		# _gateway (192.168.59.254) at 00:50:56:f5:67:e7 [ether] on ens33

		# Use regex to extract components
		# Pattern: <name> (<ip>) at <mac> [<physical>] on <interface>
		pattern = r'^(.+?)\s+\(([0-9.]+)\)\s+at\s+([0-9a-f:]+)\s+\[(\w+)\]\s+on\s+(\S+)$'
		match = re.match(pattern, line.strip())

		if match:
			name, ip, mac, physical, interface = match.groups()

			# Validate IP address
			if not (validators.ipv4(ip) or validators.ipv6(ip)):
				return

			# Set host to the name if it's not just '?'
			host = name.strip() if name.strip() != '?' else ''

			yield Ip(
				ip=ip,
				host=host,
				alive=True,
				extra_data={
					'mac': mac,
					'physical': physical,
					'interface': interface,
				}
			)
