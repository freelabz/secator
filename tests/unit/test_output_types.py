import unittest
from secator.output_types import Vulnerability


class TestCheckpoint(unittest.TestCase):
	def test_checkpoint_fields(self):
		from secator.output_types import Checkpoint
		cp = Checkpoint(task_id='abc-123', task_name='nmap_1', resume_file_path='/tmp/nmap_1_resume.cfg')
		assert cp.task_id == 'abc-123'
		assert cp.task_name == 'nmap_1'
		assert cp.resume_file_path == '/tmp/nmap_1_resume.cfg'
		assert cp._type == 'checkpoint'

	def test_checkpoint_serialization(self):
		from secator.output_types import Checkpoint
		cp = Checkpoint(task_id='abc', task_name='httpx_1', resume_file_path='/tmp/r.cfg')
		d = cp.toDict()
		assert d['task_id'] == 'abc'
		assert d['task_name'] == 'httpx_1'
		assert d['resume_file_path'] == '/tmp/r.cfg'
		assert d['_type'] == 'checkpoint'

	def test_checkpoint_context_passthrough(self):
		from secator.output_types import Checkpoint
		ctx = {'workflow_id': 'wf-1', 'scan_id': 'sc-1'}
		cp = Checkpoint(task_id='x', task_name='y', resume_file_path='', _context=ctx)
		assert cp._context['workflow_id'] == 'wf-1'


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
