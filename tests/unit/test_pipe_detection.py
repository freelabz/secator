import json
import unittest

from secator.utils import detect_secator_piped_input
from secator.output_types import Url, Port, Subdomain


class TestPipeDetection(unittest.TestCase):

	def test_detect_regular_input(self):
		"""Test that regular input is not detected as secator pipe."""
		regular_input = ['example.com', 'test.com', 'https://google.com']
		is_secator, results = detect_secator_piped_input(regular_input)
		
		self.assertFalse(is_secator)
		self.assertEqual(len(results), 0)

	def test_detect_secator_url_output(self):
		"""Test that secator URL output is correctly detected and parsed."""
		secator_input = [
			'{"_type": "url", "url": "https://example.com", "_source": "httpx", "_uuid": "test123"}',
			'{"_type": "url", "url": "https://test.com", "_source": "httpx", "_uuid": "test456"}'
		]
		is_secator, results = detect_secator_piped_input(secator_input)
		
		self.assertTrue(is_secator)
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[0], Url)
		self.assertEqual(results[0].url, 'https://example.com')
		self.assertEqual(results[1].url, 'https://test.com')

	def test_detect_secator_port_output(self):
		"""Test that secator Port output is correctly detected and parsed."""
		secator_input = [
			'{"_type": "port", "port": 80, "ip": "192.168.1.1", "host": "example.com", "state": "open", "_source": "naabu", "_uuid": "test123"}',
			'{"_type": "port", "port": 443, "ip": "192.168.1.1", "host": "example.com", "state": "open", "_source": "naabu", "_uuid": "test456"}'
		]
		is_secator, results = detect_secator_piped_input(secator_input)
		
		self.assertTrue(is_secator)
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[0], Port)
		self.assertEqual(results[0].port, 80)
		self.assertEqual(results[1].port, 443)

	def test_detect_secator_subdomain_output(self):
		"""Test that secator Subdomain output is correctly detected and parsed."""
		secator_input = [
			'{"_type": "subdomain", "host": "www.example.com", "domain": "example.com", "_source": "subfinder", "_uuid": "test123"}',
			'{"_type": "subdomain", "host": "api.example.com", "domain": "example.com", "_source": "subfinder", "_uuid": "test456"}'
		]
		is_secator, results = detect_secator_piped_input(secator_input)
		
		self.assertTrue(is_secator)
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[0], Subdomain)
		self.assertEqual(results[0].host, 'www.example.com')
		self.assertEqual(results[1].host, 'api.example.com')

	def test_detect_mixed_input(self):
		"""Test that mixed input with some invalid JSON doesn't break detection."""
		mixed_input = [
			'invalid line',
			'{"_type": "url", "url": "https://example.com", "_source": "httpx", "_uuid": "test123"}',
			'another invalid line',
			'{"_type": "url", "url": "https://test.com", "_source": "httpx", "_uuid": "test456"}'
		]
		is_secator, results = detect_secator_piped_input(mixed_input)
		
		# Should still detect as secator pipe if at least one valid secator output is found
		self.assertTrue(is_secator)
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[0], Url)

	def test_detect_empty_input(self):
		"""Test that empty input is handled gracefully."""
		empty_input = []
		is_secator, results = detect_secator_piped_input(empty_input)
		
		self.assertFalse(is_secator)
		self.assertEqual(len(results), 0)

	def test_detect_json_without_type_source(self):
		"""Test that JSON without _type and _source is not detected as secator pipe."""
		non_secator_json = [
			'{"name": "example.com", "status": "active"}',
			'{"name": "test.com", "status": "inactive"}'
		]
		is_secator, results = detect_secator_piped_input(non_secator_json)
		
		self.assertFalse(is_secator)
		self.assertEqual(len(results), 0)

	def test_detect_blank_lines(self):
		"""Test that blank lines in input are handled correctly."""
		input_with_blanks = [
			'',
			'{"_type": "url", "url": "https://example.com", "_source": "httpx", "_uuid": "test123"}',
			'   ',
			'{"_type": "url", "url": "https://test.com", "_source": "httpx", "_uuid": "test456"}',
			''
		]
		is_secator, results = detect_secator_piped_input(input_with_blanks)
		
		self.assertTrue(is_secator)
		self.assertEqual(len(results), 2)


if __name__ == '__main__':
	unittest.main()
