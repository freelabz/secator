import unittest
from secator.output_types import Vulnerability

class TestOutputTypes:
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
