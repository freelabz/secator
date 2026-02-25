import operator
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

console = Console(stderr=True, record=True)
console_stdout = Console(record=True)
# handler = RichHandler(rich_tracebacks=True)  # TODO: add logging handler


def criticity_to_color(value):
	if value == 'critical':
		value = f'[bold red3]{value.upper()}[/]'
	elif value == 'high':
		value = f'[bold orange_red1]{value.upper()}[/]'
	elif value == 'medium':
		value = f'[bold dark_orange]{value.upper()}[/]'
	elif value == 'low':
		value = f'[bold yellow1]{value.upper()}[/]'
	elif value == 'info':
		value = f'[bold green]{value.upper()}[/]'
	return value


def status_to_color(value):
	value = int(value) if value else None
	if value is None:
		return value
	if value < 400:
		value = f'[bold green]{value}[/]'
	elif value in [400, 499]:
		value = f'[bold dark_orange]{value}[/]'
	elif value >= 500:
		value = f'[bold red3]{value}[/]'
	return value


FORMATTERS = {
	'confidence': lambda x: f'[dim]{x.upper()}[/]',
	'severity': criticity_to_color,
	'cvss_score': lambda score: '' if score == -1 else f'[bold cyan]{score}[/]',
	'port': lambda port: f'[bold cyan]{port}[/]',
	'url': lambda host: f'[bold underline blue link={host}]{host}[/]',
	'stored_response_path': lambda path: f'[link=file://{path}]:pencil:[/]' if path and Path(path).exists() else '',
	'screenshot_path': lambda path: f'[link=file://{path}]:camera:[/]' if path and Path(path).exists() else '',
	'ip': lambda ip: f'[bold yellow]{ip}[/]',
	'status_code': status_to_color,
	'reference': lambda reference: f'[link={reference}]{reference}[/]' if reference else '',
	'matched_at': lambda matched_at: f'[link={matched_at}]{matched_at}[/]' if matched_at and matched_at.startswith('http') else '',  # noqa: E501
	'match': lambda match: f'[link={match}]{match}[/]' if match else '',
	'_source': lambda source: f'[bold gold3]{source}[/]'
}


class InteractiveMenu:
	"""Interactive terminal menu with arrow-key navigation and inline typing.

	Usage:
		result = InteractiveMenu("What's next?", [
			{"label": "Continue", "description": "Keep going"},
			{"label": "Custom input", "input": True},
			{"label": "Exit"},
		]).show()

	Returns:
		tuple: (index, value) where value is typed text for input options, or None.
		None: if user pressed Escape or Ctrl+C.
	"""

	def __init__(self, title, options):
		self.title = title
		self.options = options
		self.selected = 0
		self.typed = ""
		self.in_input_mode = False

	def _read_key(self, fd):
		"""Read a single keypress, handling escape sequences."""
		import os
		ch = os.read(fd, 1).decode()
		if ch == '\x1b':
			buf = os.read(fd, 10).decode()
			if not buf:
				return 'escape'
			seq = ch + buf
			if seq == '\x1b[A':
				return 'up'
			elif seq == '\x1b[B':
				return 'down'
			elif seq == '\x1b[C':
				return 'right'
			elif seq == '\x1b[D':
				return 'left'
			elif seq == '\x1bOA':
				return 'up'
			elif seq == '\x1bOB':
				return 'down'
			elif seq == '\x1bOC':
				return 'right'
			elif seq == '\x1bOD':
				return 'left'
			# Ctrl+arrows, Shift+arrows, Alt+arrows, etc. — ignore
			return 'ignore'
		elif ch == '\r' or ch == '\n':
			return 'enter'
		elif ch == '\x03':
			return 'ctrl_c'
		elif ch == '\x04':
			return 'ctrl_d'
		elif ch == '\x7f' or ch == '\x08':
			return 'backspace'
		else:
			return ch

	def _render(self):
		"""Render the menu to a string using Rich."""
		from io import StringIO
		buf = StringIO()
		render_console = Console(file=buf, force_terminal=True, width=console.width)
		w = console.width
		render_console.print(f"[dim]{'─' * w}[/]")
		render_console.print(f"[bold white]{self.title}[/]\n")
		for i, opt in enumerate(self.options):
			is_selected = i == self.selected
			prefix = "[bold cyan]❯[/]" if is_selected else " "
			num = f"[bold]{i + 1}.[/]"
			if opt.get("input"):
				if is_selected and self.in_input_mode:
					label = f"{prefix} {num} [bold]{self.typed}[/][dim]▎[/]"
				elif is_selected:
					label = f"{prefix} {num} [bold]{opt['label']}[/]"
				else:
					label = f"{prefix} {num} [dim]{opt['label']}[/]"
			else:
				if is_selected:
					label = f"{prefix} {num} [bold]{opt['label']}[/]"
				else:
					label = f"{prefix} {num} [dim]{opt['label']}[/]"
			render_console.print(label)
			if opt.get("description") and not (opt.get("input") and self.in_input_mode):
				render_console.print(f"     [gray42]{opt['description']}[/]")
		render_console.print(f"\n[dim]{'─' * w}[/]")
		return buf.getvalue()

	def _line_count(self, text):
		return text.count('\n')

	def _clear_and_exit(self, output):
		import sys
		lines = self._line_count(output)
		sys.stderr.write(f"\033[{lines}A\033[J")
		sys.stderr.flush()

	def show(self):
		"""Display the menu and handle input. Returns (index, value) or None."""
		import sys
		import tty
		import termios

		fd = sys.stdin.fileno()
		old_settings = termios.tcgetattr(fd)
		self.selected = 0
		self.typed = ""
		self.in_input_mode = False
		output = ""

		try:
			tty.setraw(fd)
			output = self._render().replace('\n', '\r\n')
			sys.stderr.write(output)
			sys.stderr.flush()

			while True:
				key = self._read_key(fd)
				prev_output = output

				if key == 'ctrl_c':
					self._clear_and_exit(prev_output)
					return None

				elif key == 'escape':
					if self.in_input_mode:
						self.in_input_mode = False
						self.typed = ""
					else:
						self._clear_and_exit(prev_output)
						return None

				elif key == 'up' and not self.in_input_mode:
					self.selected = (self.selected - 1) % len(self.options)

				elif key == 'down' and not self.in_input_mode:
					self.selected = (self.selected + 1) % len(self.options)

				elif key == 'enter':
					opt = self.options[self.selected]
					if opt.get("input") and not self.in_input_mode:
						self.in_input_mode = True
						self.typed = ""
					elif opt.get("input") and self.in_input_mode:
						self._clear_and_exit(prev_output)
						if self.typed.strip():
							return (self.selected, self.typed.strip())
						return None
					else:
						self._clear_and_exit(prev_output)
						return (self.selected, None)

				elif key == 'backspace' and self.in_input_mode:
					self.typed = self.typed[:-1]

				elif self.in_input_mode and len(key) == 1 and key.isprintable():
					self.typed += key

				elif not self.in_input_mode and key.isdigit():
					idx = int(key) - 1
					if 0 <= idx < len(self.options):
						self.selected = idx

				# Re-render
				lines = self._line_count(prev_output)
				sys.stderr.write(f"\033[{lines}A\033[J")
				output = self._render().replace('\n', '\r\n')
				sys.stderr.write(output)
				sys.stderr.flush()

		except (KeyboardInterrupt, EOFError):
			lines = self._line_count(output) if output else 0
			if lines:
				sys.stderr.write(f"\033[{lines}A\033[J")
				sys.stderr.flush()
			return None
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
			# Flush any buffered input (e.g. stray \r from raw mode)
			# to prevent it leaking into subsequent prompts
			termios.tcflush(fd, termios.TCIFLUSH)


def build_table(items, output_fields=[], exclude_fields=[], sort_by=None):
	"""Build rich table.

	Args:
		items (list): List of items.
		output_fields (list, Optional): List of fields to add.
		exclude_fields (list, Optional): List of fields to exclude.
		sort_by (tuple, Optional): Tuple of sort_by keys.

	Returns:
		rich.table.Table: rich table.
	"""
	# Sort items by one or multiple fields
	if sort_by and all(sort_by):
		items = sorted(items, key=operator.attrgetter(*sort_by))

	# Create rich table
	table = Table(show_lines=True)

	# Get table schema if any, default to first item keys
	keys = []
	if output_fields:
		keys = [k for k in output_fields if k not in exclude_fields]
		# Remove meta fields not needed in output
		if '_cls' in keys:
			keys.remove('_cls')
		if '_type' in keys:
			keys.remove('_type')
		if '_uuid' in keys:
			keys.remove('_uuid')

		# Add _source field
		if '_source' not in keys:
			keys.append('_source')

		# Create table columns
		for key in keys:
			key_str = key
			if not key.startswith('_'):
				key_str = ' '.join(key.split('_')).title()
			# TODO: remove this as it's not needed anymore
			# no_wrap = key in ['url', 'reference', 'references', 'matched_at']
			# overflow = None if no_wrap else 'fold'
			# print('key: ', key_str, 'overflow: ', overflow, 'no_wrap: ', no_wrap)
			# table.add_column(
			# 	key_str,
			# 	overflow=overflow,
			# 	min_width=10,
			# 	no_wrap=no_wrap)
			table.add_column(key_str)

	if not keys:
		table.add_column(
			'Extracted values',
			overflow=False,
			min_width=10,
			no_wrap=False)

	# Create table rows
	for item in items:
		values = []
		if keys:
			for key in keys:
				value = getattr(item, key) if keys else item
				value = FORMATTERS.get(key, lambda x: x)(value) if keys else item
				if isinstance(value, dict) or isinstance(value, list):
					value = yaml.dump(value)
				elif isinstance(value, int) or isinstance(value, float):
					value = str(value)
				values.append(value)
		else:
			values = [item]
		table.add_row(*values)
	return table
