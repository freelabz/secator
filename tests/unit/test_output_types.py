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


class TestFindingVerdictFields(unittest.TestCase):
	"""Every finding type carries the cleanup verdict fields (is_false_positive,
	confidence, confidence_nb) uniformly; non-finding types do not. `ai` (the
	conversation/action transcript) is intentionally excluded."""

	VERDICT = ('is_false_positive', 'confidence', 'confidence_nb')

	def _required_kwargs(self, cls):
		from dataclasses import fields, MISSING
		return {f.name: 'x' for f in fields(cls)
		        if f.default is MISSING and f.default_factory is MISSING and not f.name.startswith('_')}

	def test_all_finding_types_expose_verdict_fields(self):
		from secator.output_types import FINDING_TYPES
		for cls in FINDING_TYPES:
			if cls.get_name() == 'ai':
				continue
			fs = set(cls.__dataclass_fields__)
			for v in self.VERDICT:
				self.assertIn(v, fs, f'{cls.get_name()} missing {v}')

	def test_non_finding_types_do_not_gain_verdict_fields(self):
		from secator.output_types import EXECUTION_TYPES, STAT_TYPES
		for cls in EXECUTION_TYPES + STAT_TYPES:
			fs = set(cls.__dataclass_fields__)
			for v in self.VERDICT:
				self.assertNotIn(v, fs, f'{cls.get_name()} should not carry {v}')

	def test_confidence_nb_is_derived_uniformly(self):
		from secator.output_types import FINDING_TYPES
		expected = {'high': 1, 'medium': 2, 'low': 3}
		for cls in FINDING_TYPES:
			if cls.get_name() == 'ai':
				continue
			for conf, nb in expected.items():
				obj = cls(**self._required_kwargs(cls), confidence=conf)
				self.assertEqual(obj.confidence_nb, nb, f'{cls.get_name()} confidence={conf}')

	def test_verdict_fields_round_trip_todict(self):
		from secator.output_types import FINDING_TYPES
		for cls in FINDING_TYPES:
			if cls.get_name() == 'ai':
				continue
			obj = cls(**self._required_kwargs(cls), confidence='medium', is_false_positive=True)
			d = obj.toDict()
			for v in self.VERDICT:
				self.assertIn(v, d, f'{cls.get_name()} toDict missing {v}')
			self.assertTrue(d['is_false_positive'])
			self.assertEqual(cls.load(d).confidence_nb, 2)

	def test_validate_fields_accepts_verdict_on_previously_fieldless_types(self):
		# certificate + technology gained the fields -> update_finding can now set them.
		from secator.output_types import Certificate, Technology
		for cls in (Certificate, Technology):
			errs = cls.validate_fields({'is_false_positive': True, 'confidence': 'low'})
			self.assertEqual(errs, [], f'{cls.get_name()}: {errs}')
			bad = cls.validate_fields({'is_false_positive': 'nope'})
			self.assertTrue(bad)  # wrong type still rejected
