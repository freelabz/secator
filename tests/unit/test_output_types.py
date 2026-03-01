import unittest
from secator.output_types import Vulnerability, Tag
from secator.output_types.tag import is_markdown


class TestTagMarkdown(unittest.TestCase):

	def test_is_markdown_headers(self):
		text = "# Header\nSome content"
		self.assertTrue(is_markdown(text))

	def test_is_markdown_bold(self):
		text = "Some **bold** text here"
		self.assertTrue(is_markdown(text))

	def test_is_markdown_list(self):
		text = "Items:\n- Item 1\n- Item 2"
		self.assertTrue(is_markdown(text))

	def test_is_markdown_ordered_list(self):
		text = "Steps:\n1. First\n2. Second"
		self.assertTrue(is_markdown(text))

	def test_is_markdown_code(self):
		text = "Use `code` here"
		self.assertTrue(is_markdown(text))

	def test_is_markdown_link(self):
		text = "Click [here](https://example.com)"
		self.assertTrue(is_markdown(text))

	def test_is_markdown_plain_text(self):
		text = "Just some plain text without any formatting"
		self.assertFalse(is_markdown(text))

	def test_is_markdown_short_text(self):
		text = "Short"
		self.assertFalse(is_markdown(text))

	def test_tag_repr_ai_summary_not_cropped(self):
		# Create a long AI summary
		long_content = "# Summary\n" + "A" * 2000
		tag = Tag(
			name="ai_summary",
			value=long_content,
			match="summarize",
			category="ai"
		)
		repr_str = repr(tag)
		# Should contain the full content (not cropped to 1000)
		self.assertIn("A" * 100, repr_str)

	def test_tag_repr_markdown_rendered(self):
		md_content = "## Executive Summary\n\nThis is a **test** summary.\n\n- Item 1\n- Item 2"
		tag = Tag(
			name="ai_summary",
			value=md_content,
			match="summarize",
			category="ai"
		)
		repr_str = repr(tag)
		# Should render markdown (headers become styled)
		self.assertIn("Executive Summary", repr_str)


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
