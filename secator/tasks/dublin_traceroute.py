import json
import random
import shutil

from collections import Counter
from pathlib import Path

from secator.runners import Command
from secator.decorators import task
from secator.definitions import IP, CIDR_RANGE, HOST
from secator.output_types import Tag, Vulnerability, Warning, Info
from secator.utils import autodetect_type


@task()
class dublin_traceroute(Command):
	"""NAT-aware multipath tracerouting tool."""
	cmd = 'dublin-traceroute'
	input_types = [IP, CIDR_RANGE, HOST]
	input_chunk_size = 1
	output_types = [Tag]
	cwd_isolated = True
	opts = {
		'npaths': {'type': int, 'default': 20, 'help': 'Number of paths to probe'},
		'min_ttl': {'type': int, 'default': 1, 'help': 'Minimum TTL to probe'},
		'max_ttl': {'type': int, 'default': 30, 'help': 'Maximum TTL to probe'},
		'delay': {'type': int, 'default': 10, 'help': 'Inter-packet delay in milliseconds'},
		'broken_nat': {'is_flag': True, 'default': False, 'help': 'Network has a broken NAT configuration (e.g: no payload fixup)'},  # noqa: E501
		'source_port': {'type': int, 'default': 12345, 'help': 'Source ports to send packets from'}
	}
	opt_key_map = {
		'npaths': 'n',
		'min_ttl': 't',
		'max_ttl': 'T',
		'delay': 'D',
		'broken_nat': 'b',
		'source_port': 's',
	}
	github_handle = 'insomniacslk/python-dublin-traceroute'
	install_github_bin = False
	install_pre = {
		'*': ['dublin-traceroute'],
	}

	@staticmethod
	def on_init(self):
		self._cidr_input = None
		if len(self.inputs) != 1:
			return
		if autodetect_type(self.inputs[0]) == CIDR_RANGE:
			self._cidr_input = self.inputs[0]
			self.inputs[0] = self.inputs[0].split('/')[0]

	@staticmethod
	def on_cmd_opts(self, opts):
		port = opts['source_port']['value']
		default_port = opts['source_port']['conf']['default']
		if port == default_port:
			opts['source_port']['value'] = random.randint(1001, 65535)
		return opts

	@staticmethod
	def on_cmd_done(self):
		output_path = f'{self.cwd}/trace.json' if self.cwd else 'trace.json'
		if not Path(output_path).exists():
			yield Warning(message=f'Could not find output JSON {output_path}')
			self.ignore_return_code = True
			return
		self.output_path = f'{self.reports_folder}/.outputs/{self.fqn}.json'
		shutil.move(output_path, self.output_path)
		shutil.rmtree(self.cwd)
		yield Info(message=f'JSON results saved to {self.output_path}')
		with open(self.output_path, 'r') as f:
			results = json.load(f)
			all_loops = []
			flow_count = len(results['flows'])
			ttl = 0
			flow_idx = 0
			for flow_number, hops in results['flows'].items():
				full_fmt_string = f'=== Flow: {flow_idx} / Hops: {len(hops)} ==='
				flow_idx += 1
				names = []
				recv_ips = []
				for ix, hop in enumerate(hops):
					is_last = hop['is_last']
					ttl_sent = hop['sent']['ip']['ttl']
					if is_last:
						ttl = ttl_sent
					name = hop['name'] or '*'
					is_last = hop['is_last']
					rtt_usec = hop.get('rtt_usec') or 0
					received = hop.get('received') or {}
					ip_block = received.get('ip', {})
					timestamp = received.pop('timestamp', '')
					ip = ip_block.get('src', '')
					ttl_received = ip_block.get('ttl', 0)
					names.append(name)
					recv_ips.append(ip or '*')
					fmt_string = f'{ix+1:<3d} {ip:<20s} {name:<35s}'
					if name != '*':
						fmt_string += f' (RTT:{rtt_usec:<6d}us TTL -> {ttl_sent:<3d} TTL <- {ttl_received:<3d})'
					full_fmt_string += f'\n{fmt_string}'
				loops = dublin_traceroute.detect_routing_loops(recv_ips)
				all_loops.extend(loops)
				yield Tag(
					category='info',
					match=self.inputs[0],
					name='traceroute',
					value=full_fmt_string,
					_timestamp=timestamp
				)
			all_loops = list(set(all_loops))
			if all_loops:
				extra_data = {
					f'loop_{ix}': f'{pair[0]} => {pair[1]} ({count})'
					for ix, (pair, count) in enumerate(all_loops)
				}
				yield Vulnerability(
					name="Routing loops detected",
					description="Packets are bouncing between two network appliances, effectively causing network loops",
					impact="Network routing loops on firewalls can cause DoS of the target firewalls, especially when scanning with high volume and high TTLs",  # noqa: E501
					remediation="Adjust the firewall configuration to avoid infinite bouncing",
					matched_at=self.inputs[0],
					severity='critical',
					tags=['network', 'firewall'],
					extra_data=extra_data,
					confidence='high'
				)
				for pair, count in all_loops:
					yield Warning(message=f"Routing loop {pair[0]} -> {pair[1]} (appears {count} times)")
				safe = False
				unsafe = True
			else:
				yield Info(message=f"No routing loops detected over {flow_count} flows.")
				safe = True
				unsafe = False
			if self._cidr_input:
				data = {'safe': safe, 'unsafe': unsafe}
				if ttl > 0:
					data['ttl'] = ttl
				yield Tag(
					category='info',
					match=self.inputs[0],
					name='net_cidr',
					value=self._cidr_input,
					extra_data=data
				)

	@staticmethod
	def detect_routing_loops(hops):
		"""Detects routing loops by received router identity (IP), not display name.

		Distinct routers can share a reverse-DNS / display name, so counting name
		pairs can flag a false loop; counting received-IP pairs identifies the
		same physical router bouncing packets.
		"""
		pairs = [(hops[i], hops[i+1]) for i in range(len(hops)-1) if hops[i] != '*' and hops[i+1] != '*']
		return [(pair, count) for pair, count in Counter(pairs).items() if count > 2]
