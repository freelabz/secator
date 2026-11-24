"""Console exporter rendering of `--group` rows.

A grouped row is suffixed with its count and, when the finding's own line does not print the
aggregated field (e.g. `_source` for ports, urls, subdomains...), with the aggregated values too,
as a bracketed list: `[naabu, nmap] (count: 2)`.
Types whose line already prints the aggregate (ip hosts, technology matches, vulnerability
targets) must not print it twice.
"""
import unittest
from types import SimpleNamespace
from unittest import mock

from rich.console import Console

from secator.exporters.console import ConsoleExporter
from secator.query.utils import group_findings


def _render(items):
	"""Send items through the ConsoleExporter and return the plain printed lines."""
	console = Console(record=True, width=400, color_system=None)
	report = SimpleNamespace(data={'results': {'x': items}}, show_all=False)
	with mock.patch('secator.exporters.console.console_stdout', console):
		ConsoleExporter(report).send()
	return console.export_text().splitlines()


def _group(_type, records):
	from secator.output_types import OUTPUT_TYPES
	cls = {c.get_name(): c for c in OUTPUT_TYPES}[_type]
	items = [{'_type': _type, '_timestamp': i, **r} for i, r in enumerate(records)]
	return group_findings(items, list(cls._group_by), cls._group_aggregate)


class TestConsoleExporterGroupedRows(unittest.TestCase):

	def test_source_aggregate_is_shown(self):
		reps = _group('port', [
			{'ip': '192.0.2.10', 'host': 'www.example.org', 'port': 443, '_source': 'naabu'},
			{'ip': '192.0.2.10', 'host': 'www.example.org', 'port': 443, '_source': 'nmap'},
			{'ip': '198.51.100.7', 'port': 22, '_source': 'naabu'},  # hostless: ip:port key
		])
		lines = _render(reps)
		self.assertEqual(len(lines), 2)
		self.assertIn('192.0.2.10:443', lines[0])
		self.assertTrue(lines[0].endswith('[naabu, nmap] (count: 2)'), lines[0])
		self.assertTrue(lines[1].endswith('[naabu] (count: 1)'), lines[1])

	def test_every_source_aggregated_type_shows_its_sources(self):
		cases = {
			'url': {'url': 'https://www.example.org/'},
			'subdomain': {'host': 'www.example.org', 'domain': 'example.org'},
			'domain': {'domain': 'example.org'},
			'record': {'host': 'example.org', 'type': 'A', 'name': '192.0.2.10'},
			'user_account': {'site_name': 'Example', 'username': '', 'email': 'bob@example.org'},
			'certificate': {'host': 'www.example.org', 'fingerprint_sha256': 'ab' * 32},
		}
		for _type, record in cases.items():
			with self.subTest(_type=_type):
				reps = _group(_type, [{**record, '_source': 'tool1'}, {**record, '_source': 'tool2'}])
				lines = _render(reps)
				self.assertEqual(len(lines), 1, lines)
				self.assertTrue(lines[0].endswith('[tool1, tool2] (count: 2)'), lines[0])

	def test_inline_aggregate_is_not_repeated(self):
		cases = {
			'ip': ({'ip': '192.0.2.10'}, 'host', ['www.example.org', 'example.org']),
			'technology': ({'product': 'nginx', 'version': '1.24.0'}, 'match',
				['https://www.example.org/', 'https://example.com/']),
			'vulnerability': ({'name': 'Example Flaw', 'id': 'CVE-2099-0001', 'severity': 'high'}, 'matched_at',
				['192.0.2.10:22', '198.51.100.7:22']),
			'tag': ({'category': 'secret', 'name': 'aws-key', 'value': 'AKIAEXAMPLE'}, 'match',
				['https://www.example.org/app.js', 'https://example.com/app.js']),
		}
		for _type, (record, field, values) in cases.items():
			with self.subTest(_type=_type):
				reps = _group(_type, [{**record, field: v} for v in values])
				lines = _render(reps)
				self.assertEqual(len(lines), 1, lines)
				joined = ', '.join(values)
				self.assertEqual(lines[0].count(joined), 1, lines[0])
				self.assertTrue(lines[0].endswith(' (count: 2)'), lines[0])

	def test_aggregate_equal_to_another_printed_field_is_not_repeated(self):
		# An ip seen with its own address as hostname: the line hides host == ip, and the
		# aggregated value is already the printed ip, so only the count is appended.
		reps = _group('ip', [{'ip': '198.51.100.7', 'host': '198.51.100.7'}] * 2)
		self.assertTrue(_render(reps)[0].endswith('198.51.100.7 (count: 2)'))

	def test_ungrouped_rows_have_no_suffix(self):
		from secator.output_types import Port
		lines = _render([Port(port=443, ip='192.0.2.10', _source='naabu')])
		self.assertNotIn('count:', lines[0])
		self.assertNotIn('[naabu]', lines[0])


if __name__ == '__main__':
	unittest.main()

	def test_tag_rows_split_by_value(self):
		# One row per category + name + value: each value is shown once, with where it was found.
		reps = _group('tag', [
			{'category': 'secret', 'name': 'email', 'value': 'a@example.org', 'match': 'https://example.org/'},
			{'category': 'secret', 'name': 'email', 'value': 'b@example.org', 'match': 'https://example.org/'},
			{'category': 'secret', 'name': 'email', 'value': 'a@example.org', 'match': 'https://example.org/team'},
		])
		lines = _render(reps)
		self.assertEqual(len(lines), 2, lines)
		self.assertIn('a@example.org found @ https://example.org/, https://example.org/team (count: 2)', lines[0])
		self.assertIn('b@example.org found @ https://example.org/ (count: 1)', lines[1])
		for line in lines:
			self.assertNotIn('[https://', line)
