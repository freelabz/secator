import unittest
from secator.output_types import Vulnerability
from secator.output_types.error import Error
from secator.output_types.warning import Warning

class TestOutputTypes(unittest.TestCase):
	def test_merge_with(self):
		vuln1 = Vulnerability(name='CVE-2025-53020', severity='high', confidence='high', matched_at='2025-01-01')
		vuln2 = Vulnerability(name='CVE-2025-53020', severity='medium', confidence='medium', matched_at='2025-01-02')
		vuln1.merge_with(vuln2)
		assert vuln1.severity == 'medium'
		assert vuln1.confidence == 'medium'
		assert vuln1.confidence_nb == 2
		assert vuln1.severity_nb == 2
		assert vuln1.matched_at == '2025-01-02'

	def test_merge_with_dict_and_list(self):
		vuln1 = Vulnerability(name='CVE-2025-53020', tags=['nmap'], extra_data={'data': ['nmap'], 'a': 1})
		vuln2 = Vulnerability(name='CVE-2025-53020', tags=['cve'], extra_data={'data': ['cve'], 'b': 2})
		vuln1.merge_with(vuln2)
		assert vuln1.tags == ['nmap', 'cve']
		assert vuln1.extra_data == {'data': ['cve'], 'a': 1, 'b': 2}
		assert vuln1.confidence == 'low'
		assert vuln1.confidence_nb == 3
		assert vuln1.severity == 'unknown'
		assert vuln1.severity_nb == 5

	def test_merge_with_default_value(self):
		vuln1 = Vulnerability(name='CVE-2025-53020', severity='high')
		vuln2 = Vulnerability(name='CVE-2025-53020')
		vuln1.merge_with(vuln2)
		assert vuln1.severity == 'unknown'
		assert vuln1.severity_nb == 5
		assert vuln1.name == 'CVE-2025-53020'

	def test_merge_with_exclude_fields(self):
		vuln1 = Vulnerability(name='CVE-2025-53020', severity='high')
		vuln2 = Vulnerability(name='CVE-2025-53020', severity='medium')
		vuln1.merge_with(vuln2, exclude_fields=['severity', 'severity_nb'])
		assert vuln1.severity == 'high'
		assert vuln1.severity_nb == 1
		assert vuln1.name == 'CVE-2025-53020'


class TestVulnerabilityStatus(unittest.TestCase):

	def test_status_defaults_to_empty(self):
		# status is a plain field: untouched vulns default to '' (rendered/treated
		# as NEW downstream), which lets dedup carry a prior status forward generically.
		vuln = Vulnerability(name='CVE-2025-53020')
		assert vuln.status == ''

	def test_status_value_preserved_as_is(self):
		# No coercion / uppercasing — treated like any other field.
		assert Vulnerability(name='CVE-2025-53020', status='ACKNOWLEDGED').status == 'ACKNOWLEDGED'
		assert Vulnerability(name='CVE-2025-53020', status='FIXED').status == 'FIXED'

	def test_status_does_not_affect_equality(self):
		# Same identity (name/id/matched_at) but different status must still be equal (dedup-safe).
		vuln1 = Vulnerability(name='CVE-2025-53020', id='CVE-2025-53020', matched_at='host:80', status='NEW')
		vuln2 = Vulnerability(name='CVE-2025-53020', id='CVE-2025-53020', matched_at='host:80', status='FIXED')
		assert vuln1 == vuln2
		assert vuln1._compare_key() == vuln2._compare_key()


class TestErrorRich(unittest.TestCase):

	def test_error_rich_with_node_id(self):
		err = Error(message='boom', _source='nmap', _context={'node_id': 'nmap_node_1'})
		rich_str = err.__rich__()
		assert 'nmap_node_1' in rich_str
		assert 'boom' in rich_str

	def test_error_rich_falls_back_to_source(self):
		err = Error(message='boom', _source='nmap', _context={})
		rich_str = err.__rich__()
		assert 'nmap' in rich_str
		assert 'boom' in rich_str

	def test_error_rich_no_source(self):
		err = Error(message='boom')
		rich_str = err.__rich__()
		assert 'boom' in rich_str
		assert '[dim]' not in rich_str

	def test_error_rich_node_id_takes_precedence_over_source(self):
		err = Error(message='boom', _source='nmap', _context={'node_id': 'workflow_node'})
		rich_str = err.__rich__()
		assert 'workflow_node' in rich_str
		assert 'nmap' not in rich_str


class TestWarningRich(unittest.TestCase):

	def test_warning_rich_with_node_id(self):
		warn = Warning(message='watch out', _source='httpx', _context={'node_id': 'httpx_node_2'})
		rich_str = warn.__rich__()
		assert 'httpx_node_2' in rich_str
		assert 'watch out' in rich_str

	def test_warning_rich_falls_back_to_source(self):
		warn = Warning(message='watch out', _source='httpx', _context={})
		rich_str = warn.__rich__()
		assert 'httpx' in rich_str
		assert 'watch out' in rich_str

	def test_warning_rich_no_source(self):
		warn = Warning(message='watch out')
		rich_str = warn.__rich__()
		assert 'watch out' in rich_str
