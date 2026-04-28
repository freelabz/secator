import json
import unittest

from secator.utils import (
	PIPE_CHAIN_MARKER,
	extract_pipe_chain,
	get_pipe_targets_config,
	build_pipe_workflow_yaml,
)
from secator.definitions import HOST, IP, URL, HOST_PORT


class TestExtractPipeChain(unittest.TestCase):

	def test_no_metadata_returns_data_unchanged(self):
		"""Regular input lines with no pipe metadata are returned as-is."""
		data = ['example.com', 'test.com', 'https://google.com']
		regular, chain = extract_pipe_chain(data)
		self.assertEqual(regular, data)
		self.assertEqual(chain, [])

	def test_metadata_line_is_extracted(self):
		"""A #secator-pipe-chain: line is stripped from regular data and parsed."""
		chain_data = [{'task': 'subfinder', 'input_types': ['host'], 'output_types': ['subdomain']}]
		meta_line = f'{PIPE_CHAIN_MARKER}{json.dumps({"chain": chain_data})}'
		data = ['sub1.example.com', 'sub2.example.com', meta_line]

		regular, chain = extract_pipe_chain(data)

		self.assertEqual(regular, ['sub1.example.com', 'sub2.example.com'])
		self.assertEqual(chain, chain_data)

	def test_empty_input(self):
		"""Empty input returns empty lists."""
		regular, chain = extract_pipe_chain([])
		self.assertEqual(regular, [])
		self.assertEqual(chain, [])

	def test_none_input(self):
		"""None input returns empty lists gracefully."""
		regular, chain = extract_pipe_chain(None)
		self.assertEqual(regular, [])
		self.assertEqual(chain, [])

	def test_invalid_json_in_metadata_line_is_ignored(self):
		"""A malformed #secator-pipe-chain: line is silently ignored."""
		data = ['example.com', f'{PIPE_CHAIN_MARKER}not-valid-json']
		regular, chain = extract_pipe_chain(data)
		self.assertEqual(regular, ['example.com'])
		self.assertEqual(chain, [])

	def test_only_metadata_line(self):
		"""A stdin with only a metadata line yields empty regular data but valid chain."""
		chain_data = [{'task': 'naabu', 'input_types': ['host', 'ip'], 'output_types': ['port']}]
		meta_line = f'{PIPE_CHAIN_MARKER}{json.dumps({"chain": chain_data})}'
		regular, chain = extract_pipe_chain([meta_line])
		self.assertEqual(regular, [])
		self.assertEqual(chain, chain_data)

	def test_blank_lines_preserved(self):
		"""Blank lines in regular data are preserved (they're not metadata)."""
		data = ['', 'example.com', '', 'test.com']
		regular, chain = extract_pipe_chain(data)
		self.assertEqual(regular, data)
		self.assertEqual(chain, [])


class TestGetPipeTargetsConfig(unittest.TestCase):

	def test_subdomain_to_host(self):
		"""Subdomain output maps to HOST input via subdomain.host."""
		targets = get_pipe_targets_config(['subdomain'], [HOST])
		self.assertEqual(targets, ['subdomain.host'])

	def test_port_to_host_port_preferred_over_host(self):
		"""Port output prefers HOST_PORT over HOST when both are accepted."""
		targets = get_pipe_targets_config(['port'], [HOST, HOST_PORT, IP])
		self.assertEqual(len(targets), 1)
		self.assertEqual(targets[0], {'type': 'port', 'field': '{host}:{port}'})

	def test_port_to_host_only(self):
		"""Port output maps to HOST when HOST_PORT is not accepted."""
		targets = get_pipe_targets_config(['port'], [HOST, IP])
		self.assertEqual(targets, ['port.host'])

	def test_port_to_ip_only(self):
		"""Port output maps to IP when only IP is accepted."""
		targets = get_pipe_targets_config(['port'], [IP])
		self.assertEqual(targets, ['port.ip'])

	def test_ip_to_host(self):
		"""Ip output maps to HOST via ip.ip."""
		targets = get_pipe_targets_config(['ip'], [HOST])
		self.assertEqual(targets, ['ip.ip'])

	def test_url_to_url(self):
		"""Url output maps to URL input via url.url."""
		targets = get_pipe_targets_config(['url'], [URL])
		self.assertEqual(targets, ['url.url'])

	def test_no_compatible_mapping(self):
		"""Returns empty list when there is no compatible mapping."""
		targets = get_pipe_targets_config(['subdomain'], [URL])
		self.assertEqual(targets, [])

	def test_multiple_output_types(self):
		"""Multiple output types each contribute their best mapping."""
		targets = get_pipe_targets_config(['subdomain', 'ip'], [HOST])
		self.assertIn('subdomain.host', targets)
		self.assertIn('ip.ip', targets)

	def test_deduplication(self):
		"""Duplicate mappings are deduplicated in the result."""
		# Both 'ip' entries map to ip.ip for HOST — only one entry expected
		targets = get_pipe_targets_config(['ip', 'ip'], [HOST])
		self.assertEqual(targets.count('ip.ip'), 1)


class TestBuildPipeWorkflowYaml(unittest.TestCase):

	def test_empty_chain_returns_none(self):
		"""An empty chain produces no YAML."""
		yaml_content, name = build_pipe_workflow_yaml([])
		self.assertIsNone(yaml_content)
		self.assertIsNone(name)

	def test_single_task_workflow(self):
		"""A single-task chain produces valid YAML with no targets_."""
		chain = [{'task': 'subfinder', 'input_types': ['host'], 'output_types': ['subdomain']}]
		yaml_content, name = build_pipe_workflow_yaml(chain)

		self.assertEqual(name, 'pipe_subfinder')
		self.assertIn('type: workflow', yaml_content)
		self.assertIn('name: pipe_subfinder', yaml_content)
		self.assertIn('input_types:', yaml_content)
		self.assertNotIn('targets_:', yaml_content)

	def test_subfinder_naabu_httpx_chain(self):
		"""subfinder | naabu | httpx chain produces correct workflow YAML."""
		chain = [
			{'task': 'subfinder', 'input_types': ['host'], 'output_types': ['subdomain']},
			{'task': 'naabu', 'input_types': ['host', 'ip'], 'output_types': ['port']},
			{'task': 'httpx', 'input_types': ['host', 'host:port', 'ip', 'url'], 'output_types': ['url', 'subdomain']},
		]
		yaml_content, name = build_pipe_workflow_yaml(chain)

		self.assertEqual(name, 'pipe_subfinder_naabu_httpx')
		self.assertIn('name: pipe_subfinder_naabu_httpx', yaml_content)
		self.assertIn('subfinder', yaml_content)
		# naabu should reference subdomain.host
		self.assertIn('subdomain.host', yaml_content)
		# httpx should reference port with host:port format
		self.assertIn('type: port', yaml_content)
		self.assertIn("'{host}:{port}'", yaml_content)

	def test_workflow_name_uses_task_names(self):
		"""Workflow name is built from the pipe chain task names."""
		chain = [
			{'task': 'nmap', 'input_types': ['host'], 'output_types': ['port']},
			{'task': 'nuclei', 'input_types': ['host', 'url'], 'output_types': ['vulnerability']},
		]
		_, name = build_pipe_workflow_yaml(chain)
		self.assertEqual(name, 'pipe_nmap_nuclei')

	def test_description_mentions_pipe(self):
		"""Auto-generated description mentions the original pipe chain."""
		chain = [
			{'task': 'subfinder', 'input_types': ['host'], 'output_types': ['subdomain']},
			{'task': 'httpx', 'input_types': ['host'], 'output_types': ['url']},
		]
		yaml_content, _ = build_pipe_workflow_yaml(chain)
		self.assertIn('subfinder | httpx', yaml_content)


if __name__ == '__main__':
	unittest.main()
