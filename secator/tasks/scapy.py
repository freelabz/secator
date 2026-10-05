from secator.runners import PythonRunner
from secator.definitions import CIDR_RANGE, IP
from secator.output_types import Ip, Error
from secator.decorators import task

@task()
class scapy(PythonRunner):
	"""Use Scapy to scan a CIDR range and return the alive IPs."""
	input_types = [CIDR_RANGE, IP]
	output_types = [Ip]
	opts = {
		'timeout': {'type': int, 'default': 2, 'help': 'Timeout in seconds'},
		'packet_type': {'type': str, 'default': 'arp', 'help': 'Packet type to send'},
		'spoofed_ip': {'type': str, 'default': None, 'help': 'Spoofed IP address'},
		'spoofed_mac': {'type': str, 'default': None, 'help': 'Spoofed MAC address'},
	}

	def yielder(self):
		for input_ in self.inputs:
			print('Sending packet to', input_)
			response = send_packet(
				self.get_opt_value['packet_type'],
				input_,
				spoofed_ip=self.get_opt_valu['spoofed_ip'],
				spoofed_mac=self.get_opt_valu['spoofed_mac'],
				timeout=self.get_opt_valu['timeout']
			)
			print(response)
		yield 'test'

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

from scapy.all import *
import json
import time

def send_packet(packet_type, network_range, spoofed_ip=None, spoofed_mac=None, timeout=2):
	"""
	Sends a packet (ARP, ICMP, TCP SYN, or UDP) with optional spoofing and returns the response in JSON.

	Args:
		packet_type (str): "arp", "icmp", "tcp_syn", or "udp"
		network_range (str): Network range to scan
		spoofed_ip (str, optional): Spoofed source IP (for Layer 3 packets)
		spoofed_mac (str, optional): Spoofed source MAC (for Layer 2 packets)
		timeout (int, optional): Timeout in seconds (default: 2)

	Returns:
		dict: JSON response containing success status, packet details, and response (if any)
	"""
	response = {
		"success": False,
		"packet_type": packet_type,
		"network_range": network_range,
		"spoofed_ip": spoofed_ip,
		"spoofed_mac": spoofed_mac,
		"response": None,
		"error": None
	}

	try:
		if packet_type == "arp":
			# ARP (Layer 2)
			arp_pkt = ARP(pdst=network_range)
			print('Sending ARP packet to', network_range)
			if spoofed_mac:
				pkt = Ether(src=spoofed_mac) / arp_pkt
				ans, _ = srp(pkt, timeout=timeout, verbose=False)
			else:
				ans, _ = srp(arp_pkt, timeout=timeout, verbose=False)

			if ans:
				response["success"] = True
				response["response"] = [
					{
						"source_mac": ans[0][1].src,
						"source_ip": ans[0][1].psrc
					}
				]

		elif packet_type == "icmp":
			# ICMP (Layer 3)
			icmp_pkt = IP(dst=network_range) / ICMP()
			if spoofed_ip:
				icmp_pkt.src = spoofed_ip

			ans, _ = sr(icmp_pkt, timeout=timeout, verbose=False)
			if ans:
				response["success"] = True
				response["response"] = [
					{
						"source_ip": ans[0][1].src,
						"type": ans[0][1][ICMP].type,
						"code": ans[0][1][ICMP].code
					}
				]

		elif packet_type == "tcp_syn":
			# TCP SYN (Layer 3)
			tcp_pkt = IP(dst=network_range) / TCP(dport=80, flags="S")
			if spoofed_ip:
				tcp_pkt.src = spoofed_ip

			ans, _ = sr(tcp_pkt, timeout=timeout, verbose=False)
			if ans:
				response["success"] = True
				response["response"] = [
					{
						"source_ip": ans[0][1].src,
						"source_port": ans[0][1][TCP].sport,
						"flags": ans[0][1][TCP].flags
					}
				]

		elif packet_type == "udp":
			# UDP (Layer 3)
			udp_pkt = IP(dst=network_range) / UDP(dport=53)
			if spoofed_ip:
				udp_pkt.src = spoofed_ip

			ans, _ = sr(udp_pkt, timeout=timeout, verbose=False)
			if ans:
				response["success"] = True
				response["response"] = [
					{
						"source_ip": ans[0][1].src,
						"source_port": ans[0][1][UDP].sport,
						"type": "ICMP" if ICMP in ans[0][1] else "UDP"
					}
				]

		else:
			response["error"] = "Invalid packet_type. Use 'arp', 'icmp', 'tcp_syn', or 'udp'."

	except Exception as e:
		raise e
		print(e)
		response["error"] = str(e)

	return response

# Example Usage
if __name__ == "__main__":
	# Test ARP (Layer 2) with spoofed MAC
	print("--- ARP with Spoofed MAC ---")
	print(send_packet("arp", "192.168.1.1", spoofed_mac="00:11:22:33:44:55"))

	# Test ICMP (Layer 3) with spoofed IP
	print("\n--- ICMP with Spoofed IP ---")
	print(send_packet("icmp", "8.8.8.8", spoofed_ip="10.0.0.1"))

	# Test TCP SYN (Layer 3) with spoofed IP
	print("\n--- TCP SYN with Spoofed IP ---")
	print(send_packet("tcp_syn", "192.168.1.1", spoofed_ip="10.0.0.1"))

	# Test UDP (Layer 3) normally
	print("\n--- UDP (Normal) ---")
	print(send_packet("udp", "192.168.1.1"))
