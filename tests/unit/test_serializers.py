from secsy.celery import *
import unittest
import json
from secsy.serializers.dataclass import dumps_dataclass, loads_dataclass
from secsy.output_types import Port, Vulnerability


class TestCeleryCommand(unittest.TestCase):

	def test_dumps_loads(self):
		results = [
			Port(port=53, host='localhost'),
			Vulnerability(matched_at='localhost', name='CVE-123123123', provider='nmap')
		]
		results = dumps_dataclass(results)
		results = loads_dataclass(results)
		self.assertTrue(isinstance(results, list))
		self.assertEqual(len(results), 2)
		self.assertTrue(all(type(result) in [Port, Vulnerability] for result in results))
		self.assertTrue(isinstance(results, list))

	def test_dumps_loads_nested(self):
		results = {
			'info': {'name': 'test'},
			'results': {
				'ports': [
					{'port': 53, 'host': 'localhost', '_type': 'port'},
				],
				'vulnerabilities': [
					{'matched_at': 'localhost', 'name': 'CVE-123123123', 'provider': 'nmap', '_type': 'vulnerability'}
				]
			}
		}
		results = loads_dataclass(dumps_dataclass(results))
		self.assertTrue(isinstance(results['results']['ports'][0], Port))
		self.assertTrue(isinstance(results['results']['vulnerabilities'][0], Vulnerability))

	def test_dumps_loads_nested_obj(self):
		results = {
			'info': {'name': 'test'},
			'results': {
				'ports': [
					Port(port=53, host='localhost'),
				],
				'vulnerabilities': [
					Vulnerability(matched_at='localhost', name='CVE-123123123', provider='nmap')
				]
			}
		}
		results = loads_dataclass(dumps_dataclass(results))
		self.assertTrue(isinstance(results['results']['ports'][0], Port))
		self.assertTrue(isinstance(results['results']['vulnerabilities'][0], Vulnerability))