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

	def test_status_defaults_to_new(self):
		vuln = Vulnerability(name='CVE-2025-53020')
		assert vuln.status == 'NEW'

	def test_status_empty_coerces_to_new(self):
		assert Vulnerability(name='CVE-2025-53020', status='').status == 'NEW'
		assert Vulnerability(name='CVE-2025-53020', status=None).status == 'NEW'

	def test_status_unknown_coerces_to_new(self):
		assert Vulnerability(name='CVE-2025-53020', status='bogus').status == 'NEW'

	def test_status_valid_values_preserved_and_uppercased(self):
		assert Vulnerability(name='CVE-2025-53020', status='ACKNOWLEDGED').status == 'ACKNOWLEDGED'
		assert Vulnerability(name='CVE-2025-53020', status='fixed').status == 'FIXED'
		assert Vulnerability(name='CVE-2025-53020', status='  new  ').status == 'NEW'

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


class TestAiMessageField(unittest.TestCase):

	def test_ai_message_roundtrips_through_todict(self):
		from secator.output_types.ai import Ai
		msg = {'role': 'user', 'content': 'x'}
		ai = Ai(content='x', message=msg)
		assert ai.message == msg
		d = ai.toDict()
		assert d['message'] == msg

	def test_ai_message_defaults_empty(self):
		from secator.output_types.ai import Ai
		ai = Ai(content='x')
		assert ai.message == {}
		assert ai.toDict()['message'] == {}


class TestAiUnknownAiTypeRendersSafely(unittest.TestCase):
	"""Task 6 Step 4 (UI-safety guard): `tool_result` (and any other new/unknown
	ai_type not in AI_TYPES) must not raise or produce garbage when rendered.

	Ai has no __rich__/__rich_console__ of its own (unlike most other output
	types) -- __repr__ carries the full rendering logic directly, and it is
	what `console.print(item)` actually invokes for a plain object with no
	Rich protocol methods. AI_TYPES.get(self.ai_type, {...default...}) already
	falls back gracefully for an unrecognized ai_type, so no production change
	was needed here; this test locks that guarantee in so a future edit to
	__repr__ can't silently regress it back to a KeyError/crash.
	"""

	def test_tool_result_str_does_not_raise(self):
		from secator.output_types.ai import Ai
		ai = Ai(content="[run_task] 1 result(s)", ai_type="tool_result",
				message={"role": "tool", "tool_call_id": "c1", "name": "run_task", "content": "80/open"})
		# Must not raise.
		str(ai)

	def test_tool_result_repr_renders_compact_line_without_raising(self):
		from secator.output_types.ai import Ai
		ai = Ai(content="[run_task] 1 result(s)", ai_type="tool_result",
				message={"role": "tool", "tool_call_id": "c1", "name": "run_task", "content": "80/open"})
		rendered = repr(ai)
		# Falls back to the unrecognized-ai_type label, not a raw dict/garbage dump.
		# (content is rich-markup-escaped, so brackets may be backslash-escaped.)
		self.assertIn("TOOL_RESULT", rendered)
		self.assertIn("run_task", rendered)
		self.assertIn("result(s)", rendered)

	def test_tool_result_console_print_does_not_raise(self):
		"""Exercise the actual rendering path used by session.py's replay_session
		(`console.print(item, highlight=False)`) end to end."""
		from io import StringIO
		from rich.console import Console
		from secator.output_types.ai import Ai
		ai = Ai(content="[run_task] 1 result(s)", ai_type="tool_result",
				message={"role": "tool", "tool_call_id": "c1", "name": "run_task", "content": "80/open"})
		buf = StringIO()
		console = Console(file=buf, force_terminal=True, width=80)
		console.print(ai, highlight=False)  # must not raise
		self.assertIn("TOOL_RESULT", buf.getvalue())

	def test_arbitrary_unknown_ai_type_also_falls_back_safely(self):
		"""Not just `tool_result` -- ANY ai_type absent from AI_TYPES must be safe."""
		from secator.output_types.ai import Ai
		ai = Ai(content="whatever", ai_type="some_future_type_nobody_registered_yet")
		rendered = repr(ai)
		self.assertIn("SOME_FUTURE_TYPE_NOBODY_REGISTERED_YET", rendered)
		self.assertIn("whatever", rendered)
