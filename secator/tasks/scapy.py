from secator.runners import PythonRunner
from secator.definitions import CIDR_RANGE, IP
from secator.output_types import Ip, Error
from secator.decorators import task

@task()
class scapy(PythonRunner):
	"""Use Scapy to send an ARP request to a CIDR range and return the alive IPs."""
	input_types = [CIDR_RANGE, IP]
	output_types = [Ip]
	
	def yielder(self):
		for cidr_range in self.inputs:
			for finding in arp_scan(cidr_range):
				yield finding

from scapy.all import ARP, Ether, srp
import ipaddress

def arp_scan(network_range):
	network = ipaddress.ip_network(network_range, False)
	arp = ARP(pdst=str(network))
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether/arp
	try:
		result = srp(packet, timeout=2, verbose=0)[0]
		print(repr(result))
	except PermissionError as e:
		yield Error(message=(
			"You must [bold]run this task as root[/bold] to scan the network, or use "
			"[green]sudo setcap cap_net_raw=eip /usr/bin/python3.X[/green] to grant the [bold]CAP_NET_RAW[/bold] capability "
			"to the [bold]Python interpreter[/bold]."))
		return
	for sent, received in result:
		print(repr(sent))
		print(repr(received))
		rtt = received.time - sent.time
		yield Ip(
			ip=received.psrc,
			alive=True,
			extra_data={
				'protocol': 'arp',
				'rtt': f'{rtt:.2f}ms',
			},
		)
