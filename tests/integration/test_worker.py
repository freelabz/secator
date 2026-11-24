import unittest
from secator.output_types import Url, Target, Port, Tag, Technology, Vulnerability, Info, Warning, Error
from secator.runners import Command
from secator.serializers import JSONSerializer
from time import sleep
from threading import Thread
import queue


class TestWorker(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.queue = queue.Queue()
		cls.cmd = Command.execute('secator worker --use-command-runner', name='secator_worker', quiet=True, run=False)
		cls.thread = Thread(target=cls.cmd.run)
		cls.thread.start()
		sleep(3)

	@classmethod
	def tearDownClass(cls) -> None:
		cls.cmd.stop_process()
		cls.thread.join()

	def test_httpx_command(self):
		cmd = Command.execute(
			'secator x httpx secator.cloud -json', name='secator_x_httpx', process=True, quiet=True, cls_attributes={'output_types': [Target, Url, Info], 'item_loaders': [JSONSerializer()]}
		)
		# self.assertEqual(cmd.return_code, 0)  # TODO: figure out why return code is -9 when running from unittest
		self.assertEqual(cmd.errors, [])
		self.assertEqual(cmd.status, 'SUCCESS')
		self.assertEqual(len(cmd.findings), 1)
		url = Url('https://secator.cloud', status_code=200, _source='httpx')
		self.assertIn(url, cmd.findings)

	def test_host_recon(self):
		cmd = Command.execute(
			'secator w host_recon secator.cloud -json -p 443 -tid nginx-version --nuclei',
			name='secator_w_host_recon',
			process=True,
			quiet=True,
			cls_attributes={'output_types': [Target, Url, Port, Tag, Technology, Vulnerability, Info, Warning, Error], 'item_loaders': [JSONSerializer()]},
		)
		# self.assertEqual(cmd.return_code, 0)  # TODO: ditto
		self.assertGreater(len(cmd.results), 0)
		# vulns = [v for v in cmd.results if v._type == 'vulnerability']
		port = Port(port=443, ip='34.149.194.179', state='open', _source='nmap')
		url = Url('https://secator.cloud', status_code=200, _source='httpx')
		self.assertIn(port, cmd.findings)
		self.assertIn(url, cmd.findings)
		# nuclei's nginx-version template is a product detection (`tech` tag), so it yields a
		# Technology, not a Tag. The nginx patch version drifts as secator.cloud's base image
		# updates (e.g. 1.30.3 -> 1.30.4), so assert the stable fields instead of the version.
		self.assertTrue(
			any(
				t._type == 'technology'
				and t._source == 'nuclei'
				and t.product == 'nginx'
				and t.match == 'https://secator.cloud'
				and t.version
				for t in cmd.findings
			),
			'expected a versioned nginx technology from nuclei @ https://secator.cloud',
		)
		# self.assertEqual(vulns, [])

	# def test_pd_pipe(self):
	# 	cmd = Command.execute(
	# 		'secator x subfinder vulnweb.com | secator x nmap | secator x httpx | secator x katana | secator x httpx | secator x gf --pattern lfi -fmt "{match}" | secator x dalfox'
	# 	)
