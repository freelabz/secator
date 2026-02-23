"""AI output type for displaying prompts, responses, summaries, and suggestions."""
import re
import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


def is_markdown(text: str) -> bool:
	"""Detect if text contains Markdown formatting."""
	if not text or len(text) < 10:
		return False

	markdown_patterns = [
		r'^#{1,6}\s+',          # Headers: # Header
		r'\*\*[^*]+\*\*',       # Bold: **text**
		r'^\s*[-*+]\s+',        # Unordered lists: - item
		r'^\s*\d+\.\s+',        # Ordered lists: 1. item
		r'^\s*>\s+',            # Blockquotes: > quote
		r'`[^`]+`',             # Inline code: `code`
		r'```',                 # Code blocks: ```
		r'\[.+\]\(.+\)',        # Links: [text](url)
	]

	for pattern in markdown_patterns:
		if re.search(pattern, text, re.MULTILINE):
			return True
	return False


def render_markdown_for_rich(text: str) -> str:
	"""Render Markdown text for rich console output."""
	from rich.console import Console
	from rich.markdown import Markdown
	from io import StringIO

	console = Console(file=StringIO(), force_terminal=True, width=120)
	md = Markdown(text)
	console.print(md)
	return console.file.getvalue()


# AI content type configurations
AI_TYPES = {
	'prompt': {'label': 'USER PROMPT', 'color': 'blue'},
	'response': {'label': 'AGENT', 'color': 'red'},
	'summary': {'label': 'SUMMARY', 'color': 'green'},
	'suggestion': {'label': 'SUGGESTIONS', 'color': 'cyan'},
	'attack_summary': {'label': 'ATTACK SUMMARY', 'color': 'yellow'},
	'task': {'label': 'TASK', 'color': 'magenta'},
	'workflow': {'label': 'WORKFLOW', 'color': 'magenta'},
	'scan': {'label': 'SCAN', 'color': 'magenta'},
	'shell': {'label': 'SHELL', 'color': 'magenta'},
	'shell_output': {'label': 'SHELL OUTPUT', 'color': 'white'},
	'stopped': {'label': 'STOPPED', 'color': 'orange3'},
	'report': {'label': 'REPORT', 'color': 'cyan'},
}


@dataclass
class Ai(OutputType):
	"""Output type for AI-generated content with markdown support."""
	content: str
	ai_type: str = field(default='response')  # prompt, response, summary, suggestion, attack_summary
	mode: str = field(default='', compare=False)  # summarize, suggest, attack
	model: str = field(default='', compare=False)
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='ai', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['ai_type', 'mode', 'content']
	_sort_by = ('_timestamp',)

	def __repr__(self) -> str:
		# Get type configuration
		type_config = AI_TYPES.get(self.ai_type, {'label': self.ai_type.upper(), 'color': 'white'})
		label = type_config['label']
		color = type_config['color']

		# For 'response' type, include iteration in header
		if self.ai_type == 'response' and 'iteration' in self.extra_data:
			iteration = self.extra_data.get('iteration', '')
			max_iter = self.extra_data.get('max_iterations', '')
			if max_iter:
				label = f'{label} {iteration}/{max_iter}'
			else:
				label = f'{label} {iteration}'

		# Build header with robot icon
		s = rf'🤖 \[[bold {color}]{label}[/]]'

		# Filter out iteration fields from extra_data display
		display_extra = {k: v for k, v in self.extra_data.items()
						 if k not in ('iteration', 'max_iterations')}

		# Render content with markdown support
		content = self.content
		if is_markdown(content):
			# Markdown is pre-rendered to ANSI by render_markdown_for_rich
			header = rich_to_ansi(s)
			md_rendered = render_markdown_for_rich(content)
			md_indented = '\n    ' + md_rendered.replace('\n', '\n    ')
			result = header + md_indented.rstrip()
			if display_extra:
				for k, v in display_extra.items():
					result += '\n    ' + rich_to_ansi(f'[bold yellow]{_s(k)}[/]: [yellow]{_s(v)}[/]')
			return result

		# Build full Rich markup string, then convert once
		content_indented = content.replace('\n', '\n    ')
		s += f' {_s(content_indented)}'
		if display_extra:
			for k, v in display_extra.items():
				s += f'\n    [bold yellow]{_s(k)}[/]: [yellow]{_s(v)}[/]'
		return rich_to_ansi(s)
