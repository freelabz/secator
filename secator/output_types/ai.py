"""AI output type for displaying prompts, responses, summaries, and suggestions."""
import re
import shutil
import time

from dataclasses import dataclass, field
from io import StringIO
from rich.panel import Panel
from rich.text import Text
from rich.console import Console
from rich.markdown import Markdown

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s, format_token_count, format_object


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
	"""Render Markdown text for rich console output, optionally in a Panel."""
	terminal_width = shutil.get_terminal_size().columns
	console = Console(file=StringIO(), force_terminal=True, width=terminal_width)
	md = Markdown(text)
	if title:
		panel = Panel(md, title=title, title_align="left", border_style="dim", padding=(1, 2))
		console.print(panel)
	else:
		console.print(md)
	return console.file.getvalue()


# AI content type configurations
AI_TYPES = {
	'prompt': {'label': '❯', 'color': 'red'},
	'response': {'label': '🧠', 'color': 'white'},
	'chat_compacted': {'label': '📦', 'color': 'orange3'},
	'task': {'label': '🟢', 'color': 'magenta'},
	'workflow': {'label': '🟢', 'color': 'magenta'},
	'shell': {'label': '🟢', 'color': 'magenta'},
	'add_finding': {'label': '🟢', 'color': 'magenta'},
	'shell_output': {'label': '◀', 'color': 'dim white'},
	'query': {'label': '🟢', 'color': 'magenta'},
	'stopped': {'label': '🛑', 'color': 'orange3'},
	'follow_up': {'label': '[FOLLOW UP]', 'color': 'orange3'},
}

ACTION_TYPES = ('task', 'workflow', 'shell', 'add_finding', 'query', 'stopped')


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

	def __rich__(self) -> str:
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
					parts.append(f' • {format_token_count(tokens, icon=icon)}')
				if cost:
					parts.append(f' - ${cost:.4f}')
				usage_str = ' '.join(parts)

		# Action types
		if self.ai_type in ACTION_TYPES:
			action_label = self.ai_type
			if self.ai_type == 'stopped':
				action_label = 'done'
			line = f'{s}[bold blue]{action_label.capitalize().replace('_', ' ')}[/]'
			content = _s(self.content)
			if self.ai_type in ['task', 'workflow', 'scan']:
				colors = {
					'task': 'bold gold3',
					'workflow': 'bold dark_orange3',
					'scan': 'bold red',
				}
				color = colors[self.ai_type]
				content = f'[{color}]{content}[/]'
			targets = self.extra_data.get('targets')
			opts = self.extra_data.get('opts')
			results = self.extra_data.get('results')
			limit = self.extra_data.get('limit')
			if targets:
				if len(targets) == 1:
					content += f' on [cyan]{targets[0]}[/]'
				else:
					content += f' on {format_object(targets, "cyan")}'
			if opts:
				content += f' with opts{format_object(opts, "yellow")}'
			line += f'({content})'
			if results is not None:
				line += f' -> [yellow]{_s(results)} results[/]'
			if limit is not None:
				line += f' ([dim yellow]limit: {_s(limit)}[/])'
			if self.ai_type == 'prompt':
				line = f'[on gray19]{line}[/]'
			return '\n' + line

		# Filter out internal fields from extra_data display
		display_extra = {k: v for k, v in self.extra_data.items()
						 if k not in ('iteration', 'max_iterations', 'tokens', 'cost')}

		# Build suffix (usage + extra_data) as Rich markup
		suffix = ''
		if usage_str:
			suffix += f' [gray42]{usage_str}[/]'
		if display_extra:
			parts = [f'[bold yellow]{_s(k)}[/]: [yellow]{_s(v)}[/]' for k, v in display_extra.items()]
			suffix += f'  {", ".join(parts)}'

		# Shell output: dim text in a panel, truncated to 10 lines
		if self.ai_type == 'shell_output':
			buf = StringIO()
			terminal_width = shutil.get_terminal_size().columns
			render_console = Console(file=buf, force_terminal=True, width=terminal_width)
			content = self.content
			lines = content.split('\n')
			max_lines = 10
			if len(lines) > max_lines:
				content = '\n'.join(lines[:max_lines])
				content += f'\n... ({len(lines) - max_lines} more lines truncated)'
			text = Text(content, style="gray42")
			panel = Panel(text, title=f"{s}", title_align="left", border_style="gray42", padding=(0, 1))
			render_console.print(panel)
			return buf.getvalue().rstrip()

		# Render content with markdown support
		content = self.content
		if is_markdown(content):
			# Markdown rendered inside a Rich Panel with header as title
			title = s + suffix
			return '\n' + render_markdown_for_rich(content, title=title).rstrip()

		# Build full Rich markup string, then convert once
		content_indented = content.replace('\n', '\n    ')
		if self.ai_type == 'prompt':
			s = f'[on gray19] {s} {_s(content_indented)} [/]'
		else:
			s += f' {_s(content_indented)}'
		s += suffix
		return '\n' + s

	def __repr__(self) -> str:
		return rich_to_ansi(self.__rich__())
