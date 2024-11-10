import unittest
from secator.output_types import Url, Target, Port, Vulnerability, Info
from secator.runners import Command
from secator.serializers import JSONSerializer
from time import sleep
from threading import Thread
import queue

class TestWorker(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		cls.queue = queue.Queue()
		cls.cmd = Command.execute('secator worker', name='secator_worker', quiet=True, run=False)
		cls.thread = Thread(target=cls.cmd.run)
		cls.thread.start()
		sleep(3)

	@classmethod
	def tearDownClass(cls) -> None:
		cls.cmd.stop_process()
		cls.thread.join()

	def test_httpx(self):
		cmd = Command.execute(
			'secator x httpx testphp.vulnweb.com -json',
			name='secator_x_httpx',
			no_process=False,
			quiet=True,
			cls_attributes={'output_types': [Target, Url, Info], 'item_loaders': [JSONSerializer()]}
		)
		# self.assertEqual(cmd.return_code, 0)  # TODO: figure out why return code is -9 when running from unittest
		self.assertEqual(len(cmd.findings), 1)
		url = Url(
			'http://testphp.vulnweb.com',
			status_code=200,
			title='Home of Acunetix Art',
			webserver='nginx',
			tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'],
			content_type='text/html',
			content_length=4958,
			_source='httpx'
		)
		self.assertIn(url, cmd.results)

	def test_host_recon(self):
		cmd = Command.execute(
			'secator w host_recon vulnweb.com -json -p 80 -tid nginx-version',
			name='secator_w_host_recon',
			no_process=False,
			quiet=True,
			cls_attributes={'output_types': [Target, Url, Port, Vulnerability, Info], 'item_loaders': [JSONSerializer()]}
		)
		# self.assertEqual(cmd.return_code, 0)  # TODO: ditto
		self.assertGreater(len(cmd.results), 0)
		port = Port(
			port=80,
			ip="44.228.249.3",
			state="open",
			service_name="nginx/1.19.0",
			_source="nmap"
		)
		url = Url(
			'http://vulnweb.com',
			status_code=200,
			title='Acunetix Web Vulnerability Scanner - Test Websites',
			webserver='nginx/1.19.0',
			tech=['Nginx:1.19.0'],
			content_type='text/html',
			content_length=4018,
			_source='httpx'
		)
		vuln = Vulnerability(
			name='nginx-version',
			provider='',
			id='',
			matched_at='http://vulnweb.com',
			confidence='high',
			confidence_nb=4,
			severity_nb=4,
			severity='info',
			tags=['tech', 'nginx'],
			_source='nuclei_url'
		)
		self.assertIn(port, cmd.results)
		self.assertIn(url, cmd.results)
		self.assertIn(vuln, cmd.results)

	# def test_pd_pipe(self):
	# 	cmd = Command.execute(
	# 		'secator x subfinder vulnweb.com | secator x nmap | secator x httpx | secator x katana | secator x httpx | secator x gf --pattern lfi -fmt "{match}" | secator x dalfox'
	# 	)
