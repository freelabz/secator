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
	# Pre-process: collapse 3+ consecutive newlines to 2 (single blank line)
	text = re.sub(r'\n{3,}', '\n\n', text)
	terminal_width = shutil.get_terminal_size().columns
	console = Console(file=StringIO(), force_terminal=True, width=terminal_width)
	md = Markdown(text)
	if title:
		panel = Panel(md, title=title, title_align="left", border_style="dim", padding=(0, 1))
		console.print(panel)
	else:
		console.print(md)
	# Post-process: collapse consecutive blank lines in rendered output
	output = console.file.getvalue()
	output = re.sub(r'(\n\s*){3,}', '\n\n', output)
	return output


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
	summary: bool = field(default=False, compare=False)
	status: str = field(default='', compare=False)
	answer: str = field(default='', compare=False)
	choices: list = field(default_factory=list, compare=False)
	session_id: str = field(default='', compare=False)
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
		# Internal-only types (not displayed)
		if self.ai_type == 'token_usage':
			return ' '

		# Get type configuration
		type_config = AI_TYPES.get(self.ai_type, {'label': self.ai_type.upper(), 'color': 'white'})
		label = type_config['label']
		color = type_config['color']

		# For 'response' and 'prompt' types, include iteration in header
		if self.ai_type in ('response', 'prompt'):
			if 'iteration' in self.extra_data:
				iteration = self.extra_data.get('iteration', '')
				max_iter = self.extra_data.get('max_iterations', '')
				if max_iter:
					label = f'{label} [gray42]({iteration}/{max_iter})[/]'
				else:
					label = f'{label} [gray42]({iteration})[/]'

		# Build header with robot icon
		s = rf'[bold {color}]{label}[/]'

		# Add session name or subagent label for prompt and response types
		subagent = self._context.get('subagent')
		session_name = self._context.get('name')
		if self.ai_type in ('response', 'prompt') and (session_name or subagent):
			name_label = _s(session_name or (subagent if isinstance(subagent, str) else 'subagent'))
			s += f' [bold orange4]{name_label}[/]'

		# Build usage info string (dimmed, at end) for response and prompt types
		usage_str = ''
		if self.ai_type in ('response', 'prompt'):
			tokens = self.extra_data.get('tokens')
			cost = self.extra_data.get('cost')
			context_window = self.extra_data.get('context_window')
			by_role = self.extra_data.get('by_role')
			icon = 'arrow_up'
			if self.ai_type == 'response':
				icon = 'arrow_down'
			if tokens or cost:
				parts = []
				if tokens:
					token_part = format_token_count(tokens, icon=icon, compact=True)
					if context_window:
						token_part += f'/[dim red]{format_token_count(context_window, compact=True)}[/]'
					parts.append(f' • {token_part}')
				if by_role:
					role_parts = []
					for role in ('system', 'user', 'assistant', 'tool'):
						if role in by_role:
							role_parts.append(f'[orange4]{role}[/]:{format_token_count(by_role[role], compact=True)}')
					if role_parts:
						parts.append(f'({" | ".join(role_parts)})')
				if cost:
					parts.append(f'- ${cost:.4f}')
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
			return rich_to_ansi(line)

		# Filter out internal fields from extra_data display
		display_extra = {k: v for k, v in self.extra_data.items()
						 if k not in ('iteration', 'max_iterations', 'tokens', 'cost', 'context_window', 'by_role')}

		# Build suffix (usage + extra_data) as Rich markup
		suffix = ''
		if usage_str:
			suffix += f' [gray42]{usage_str}[/]'
		if display_extra:
			parts = [f'[bold yellow]{_s(k)}[/]: [yellow]{_s(v)}[/]' for k, v in display_extra.items()]
			suffix += f'  {", ".join(parts)}'

		# Shell output: dim text in a panel, truncated to 3 lines and capped width
		if self.ai_type == 'shell_output':
			buf = StringIO()
			terminal_width = shutil.get_terminal_size().columns
			render_console = Console(file=buf, force_terminal=True, width=terminal_width)
			content = self.content
			lines = content.split('\n')
			max_lines = 3
			# Cap line width (account for panel borders and padding)
			max_line_width = terminal_width - 6
			capped_lines = []
			for line in lines[:max_lines]:
				if len(line) > max_line_width:
					capped_lines.append(line[:max_line_width - 5] + '[...]')
				else:
					capped_lines.append(line)
			content = '\n'.join(capped_lines)
			if len(lines) > max_lines:
				content += f'\n… +{len(lines) - max_lines} lines'
			text = Text(content, style="gray42")
			panel = Panel(text, title=f"{s}", title_align="left", border_style="gray42", padding=(0, 1))
			render_console.print(panel)
			return buf.getvalue().rstrip()

		# Render content with markdown support
		content = self.content

		# Response type: always render in a Panel with title
		if self.ai_type == 'response':
			title = s + suffix
			return '\n' + render_markdown_for_rich(content, title=title).rstrip()

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
		return '\n' + rich_to_ansi(s)
