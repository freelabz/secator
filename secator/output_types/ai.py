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


def render_markdown_for_rich(text: str, title: str = '') -> str:
	"""Render Markdown text for rich console output, wrapped in a Panel."""
	from rich.console import Console
	from rich.markdown import Markdown
	from rich.panel import Panel
	from io import StringIO

	console = Console(file=StringIO(), force_terminal=True, width=120)
	md = Markdown(text)
	panel = Panel(md, title=title, title_align="left", border_style="dim", padding=(1, 2))
	console.print(panel)
	return console.file.getvalue()


# AI content type configurations
AI_TYPES = {
	'prompt': {'label': '❯', 'color': 'blue'},
	'response': {'label': '🧠', 'color': 'red'},
	'summary': {'label': '🧠', 'color': 'white'},
	'suggestion': {'label': '🧠', 'color': 'cyan'},
	'attack_summary': {'label': '🧠', 'color': 'yellow'},
	'task': {'label': '☐', 'color': 'magenta'},
	'workflow': {'label': '☐', 'color': 'magenta'},
	'scan': {'label': '☐', 'color': 'magenta'},
	'shell': {'label': '☐', 'color': 'magenta'},
	'shell_output': {'label': '🐚', 'color': 'dim white'},
	'query': {'label': '❓', 'color': 'magenta'},
	'stopped': {'label': '🛑', 'color': 'orange3'},
	'report': {'label': 'AI REPORT', 'color': 'cyan'}
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
				label = f'{label} [gray42]({iteration}/{max_iter})[/]'
			else:
				label = f'{label} [gray42]({iteration})[/]'

		# Build header with robot icon
		s = rf'[bold {color}]{label}[/]'

		# Build usage info string (dimmed, at end) for response and prompt types
		usage_str = ''
		if self.ai_type in ('response', 'prompt'):
			tokens = self.extra_data.get('tokens')
			cost = self.extra_data.get('cost')
			icon = 'arrow_up'
			if self.ai_type == 'response':
				icon = 'arrow_down'
			if tokens or cost:
				parts = []
				if tokens:
					# Format tokens in K format (e.g., 8.8k)
					if tokens >= 1000:
						parts.append(f' • :{icon}: {tokens/1000:.1f}k tokens')
					else:
						parts.append(f' • {tokens} tokens')
				if cost:
					parts.append(f' - ${cost:.4f}')
				usage_str = ' '.join(parts)

		# Filter out internal fields from extra_data display
		display_extra = {k: v for k, v in self.extra_data.items()
						 if k not in ('iteration', 'max_iterations', 'tokens', 'cost')}

		# Build suffix (usage + extra_data) as Rich markup
		suffix = ''
		if usage_str:
			suffix += f' [gray42]{usage_str}[/]'
		if display_extra:
			for k, v in display_extra.items():
				suffix += f'\n    [bold yellow]{_s(k)}[/]: [yellow]{_s(v)}[/]'

		# Render content with markdown support
		content = self.content
		if is_markdown(content):
			# Markdown rendered inside a Rich Panel with header as title
			title = s + suffix
			return render_markdown_for_rich(content, title=title).rstrip()

		# Build full Rich markup string, then convert once
		content_indented = content.replace('\n', '\n    ')
		if self.ai_type == 'prompt':
			s = f'[on grey23] {s} {_s(content_indented)} [/]'
		else:
			s += f' {_s(content_indented)}'
		s += suffix
		return rich_to_ansi(s)
