import codecs
import operator
from contextlib import nullcontext
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

console = Console(stderr=True, record=True)
console_stdout = Console(record=True)


def maybe_status(*args, **kwargs):
	"""Return console.status() normally, or nullcontext() when a live display is already active or in a worker."""
	from secator.definitions import IN_WORKER
	if IN_WORKER or console._live is not None:
		return nullcontext()
	return console.status(*args, **kwargs)
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
	elif 400 <= value < 500:
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


class FullScreenPrompt:
	"""Full-screen terminal prompt input with multiline support.

	Renders a centered prompt area that fills the terminal, similar to
	Claude Code's input style. Supports multiline editing with word wrap
	display.

	Usage:
		result = FullScreenPrompt("What do you want to do?").show()

	Returns:
		str: The user's input text, or None if cancelled.
	"""

	def __init__(self, title="Enter your prompt", placeholder="Type your prompt here..."):
		self.title = title
		self.placeholder = placeholder
		self.lines = [""]
		self.cursor_line = 0
		self.cursor_col = 0
		self._decoder = codecs.getincrementaldecoder('utf-8')(errors='ignore')

	def _read_key(self, fd):
		"""Read a single keypress, handling escape sequences."""
		import os
		import select
		ch = self._decoder.decode(os.read(fd, 1), final=False)
		if not ch:
			return 'ignore'
		if ch == '\x1b':
			if not select.select([fd], [], [], 0.03)[0]:
				return 'escape'
			seq = ch + os.read(fd, 2).decode(errors='ignore')
			if seq in ('\x1b[A', '\x1bOA'):
				return 'up'
			elif seq in ('\x1b[B', '\x1bOB'):
				return 'down'
			elif seq in ('\x1b[C', '\x1bOC'):
				return 'right'
			elif seq in ('\x1b[D', '\x1bOD'):
				return 'left'
			elif seq == '\x1b[3':
				# Read the ~ for delete key
				os.read(fd, 1)
				return 'delete'
			return 'ignore'
		elif ch == '\r' or ch == '\n':
			return 'enter'
		elif ch == '\x03':
			return 'ctrl_c'
		elif ch == '\x04':
			return 'ctrl_d'
		elif ch == '\t':
			return 'tab'
		elif ch == '\x7f' or ch == '\x08':
			return 'backspace'
		else:
			return ch

	def _render(self):
		"""Render the prompt to a string using Rich."""
		from io import StringIO
		buf = StringIO()
		w = console.width
		h = console.height
		render_console = Console(file=buf, force_terminal=True, width=w)

		# Top border
		render_console.print(f"[dim]{'─' * w}[/]")
		render_console.print()

		# Title
		render_console.print(f"  [bold cyan]{self.title}[/]")
		render_console.print()

		# Input area
		text = '\n'.join(self.lines)
		if text:
			for i, line in enumerate(self.lines):
				if i == self.cursor_line:
					# Show cursor
					before = line[:self.cursor_col]
					after = line[self.cursor_col:]
					render_console.print(f"  [bold white]  {before}[/][on white] [/][bold white]{after}[/]")
				else:
					render_console.print(f"  [white]  {line}[/]")
		else:
			render_console.print(f"  [dim]  {self.placeholder}[/][on white] [/]")

		# Fill remaining space
		used_lines = 5 + max(len(self.lines), 1)
		remaining = h - used_lines - 3
		for _ in range(max(0, remaining)):
			render_console.print()

		# Bottom help
		render_console.print()
		render_console.print("[gray42]  Ctrl+D: submit  •  Enter: new line  •  Esc: cancel[/]")
		render_console.print(f"[dim]{'─' * w}[/]")

		return buf.getvalue()

	def _line_count(self, text):
		return text.count('\n')

	def show(self):
		"""Display the prompt and handle input. Returns text or None."""
		import sys
		import tty
		import termios

		if not sys.stdin.isatty():
			return None

		fd = sys.stdin.fileno()
		old_settings = termios.tcgetattr(fd)

		try:
			tty.setraw(fd)

			# Clear screen and render
			sys.stderr.write("\033[2J\033[H")
			output = self._render().replace('\n', '\r\n')
			sys.stderr.write(output)
			sys.stderr.flush()

			while True:
				key = self._read_key(fd)

				if key == 'ctrl_c' or key == 'escape':
					# Restore screen
					sys.stderr.write("\033[2J\033[H")
					sys.stderr.flush()
					return None

				elif key == 'ctrl_d':
					# Submit
					text = '\n'.join(self.lines).strip()
					sys.stderr.write("\033[2J\033[H")
					sys.stderr.flush()
					return text if text else None

				elif key == 'enter':
					# New line
					rest = self.lines[self.cursor_line][self.cursor_col:]
					self.lines[self.cursor_line] = self.lines[self.cursor_line][:self.cursor_col]
					self.cursor_line += 1
					self.lines.insert(self.cursor_line, rest)
					self.cursor_col = 0

				elif key == 'backspace':
					if self.cursor_col > 0:
						line = self.lines[self.cursor_line]
						self.lines[self.cursor_line] = line[:self.cursor_col - 1] + line[self.cursor_col:]
						self.cursor_col -= 1
					elif self.cursor_line > 0:
						# Merge with previous line
						prev_len = len(self.lines[self.cursor_line - 1])
						self.lines[self.cursor_line - 1] += self.lines[self.cursor_line]
						self.lines.pop(self.cursor_line)
						self.cursor_line -= 1
						self.cursor_col = prev_len

				elif key == 'delete':
					line = self.lines[self.cursor_line]
					if self.cursor_col < len(line):
						self.lines[self.cursor_line] = line[:self.cursor_col] + line[self.cursor_col + 1:]
					elif self.cursor_line < len(self.lines) - 1:
						self.lines[self.cursor_line] += self.lines[self.cursor_line + 1]
						self.lines.pop(self.cursor_line + 1)

				elif key == 'left':
					if self.cursor_col > 0:
						self.cursor_col -= 1
					elif self.cursor_line > 0:
						self.cursor_line -= 1
						self.cursor_col = len(self.lines[self.cursor_line])

				elif key == 'right':
					if self.cursor_col < len(self.lines[self.cursor_line]):
						self.cursor_col += 1
					elif self.cursor_line < len(self.lines) - 1:
						self.cursor_line += 1
						self.cursor_col = 0

				elif key == 'up':
					if self.cursor_line > 0:
						self.cursor_line -= 1
						self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))

				elif key == 'down':
					if self.cursor_line < len(self.lines) - 1:
						self.cursor_line += 1
						self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))

				elif key == 'tab':
					# Insert spaces for tab
					self.lines[self.cursor_line] = (
						self.lines[self.cursor_line][:self.cursor_col]
						+ '    '
						+ self.lines[self.cursor_line][self.cursor_col:]
					)
					self.cursor_col += 4

				elif len(key) == 1 and key.isprintable():
					self.lines[self.cursor_line] = (
						self.lines[self.cursor_line][:self.cursor_col]
						+ key
						+ self.lines[self.cursor_line][self.cursor_col:]
					)
					self.cursor_col += 1

				elif key == 'ignore':
					continue
				else:
					continue

				# Re-render
				sys.stderr.write("\033[2J\033[H")
				output = self._render().replace('\n', '\r\n')
				sys.stderr.write(output)
				sys.stderr.flush()

		except (KeyboardInterrupt, EOFError):
			sys.stderr.write("\033[2J\033[H")
			sys.stderr.flush()
			return None
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
			termios.tcflush(fd, termios.TCIFLUSH)


class InteractiveMenu:
	"""Interactive terminal menu with arrow-key navigation and inline typing.

	Usage:
		result = InteractiveMenu("What's next?", [
			{"label": "Continue", "description": "Keep going"},
			{"label": "Custom input", "input": True},
			{"label": "Exit"},
		]).show()

	Returns:
		tuple: (index_or_indices, value) where index_or_indices is an int (single-select)
			or a sorted list of ints (multi-select via Space). value is typed text or None.
		None: if user pressed Escape or Ctrl+C.
	"""

	def __init__(self, title, options, description=""):
		self.title = title
		self.description = description
		self.options = options
		self.selected = 0
		self.checked = set()
		self.typed = ""
		self.in_input_mode = False
		self._decoder = codecs.getincrementaldecoder('utf-8')(errors='ignore')

	def _read_key(self, fd):
		"""Read a single keypress, handling escape sequences."""
		import os
		import select
		ch = self._decoder.decode(os.read(fd, 1), final=False)
		if not ch:
			return 'ignore'
		if ch == '\x1b':
			# Plain ESC: no follow-up bytes within a short timeout.
			if not select.select([fd], [], [], 0.03)[0]:
				return 'escape'
			seq = ch + os.read(fd, 2).decode(errors='ignore')
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
		elif ch == '\t':
			return 'tab'
		elif ch == '\x7f' or ch == '\x08':
			return 'backspace'
		elif ch == ' ':
			return 'space'
		else:
			return ch

	def _render(self):
		"""Render the menu to a string using Rich, with scrolling viewport."""
		import shutil
		from io import StringIO
		buf = StringIO()
		render_console = Console(file=buf, force_terminal=True, width=console.width)
		w = console.width

		# Calculate viewport: reserve lines for chrome (title, footer, separators)
		term_height = shutil.get_terminal_size().lines
		chrome_lines = 6  # top separator + title + blank + footer + hints + bottom separator
		max_visible = max(3, (term_height - chrome_lines))

		# Compute visible window around selected item
		total = len(self.options)
		if total <= max_visible:
			win_start, win_end = 0, total
		else:
			half = max_visible // 2
			win_start = self.selected - half
			win_end = win_start + max_visible
			if win_start < 0:
				win_start, win_end = 0, max_visible
			elif win_end > total:
				win_end = total
				win_start = total - max_visible

		render_console.print(f"[dim]{'─' * w}[/]")
		render_console.print(f"[bold white]{self.title}[/]")
		if self.description:
			render_console.print(f"[dim]{self.description}[/]")
		render_console.print()

		if win_start > 0:
			render_console.print(f"  [dim]↑ {win_start} more[/]")

		for i in range(win_start, win_end):
			opt = self.options[i]
			is_selected = i == self.selected
			is_checked = i in self.checked
			prefix = "[bold cyan]❯[/]" if is_selected else " "
			check = "[bold green]✓[/] " if is_checked else "  " if self.checked else ""
			num = f"[bold]{i + 1}.[/]"
			if opt.get("input"):
				if is_selected and self.in_input_mode:
					if self.typed:
						label = f"{prefix} {num} {check}[bold]{self.typed}[/][dim]▎[/]"
					else:
						label = f"{prefix} {num} {check}[gray42]{opt['label']}[/][dim]▎[/]"
				elif is_selected:
					label = f"{prefix} {num} {check}[bold]{opt['label']}[/]"
				else:
					label = f"{prefix} {num} {check}[dim]{opt['label']}[/]"
			else:
				if is_selected:
					label = f"{prefix} {num} {check}[bold]{opt['label']}[/]"
				else:
					label = f"{prefix} {num} {check}[dim]{opt['label']}[/]"
			render_console.print(label)

		if win_end < total:
			render_console.print(f"  [dim]↓ {total - win_end} more[/]")

		if self.in_input_mode:
			render_console.print("\n[gray42]  Enter: confirm  •  Esc: cancel[/]")
		else:
			has_selectable = any(opt.get("selectable") for opt in self.options)
			parts = ["Enter: confirm"]
			if has_selectable:
				parts.append("Space: toggle")
			parts.append("Tab: edit prompt")
			parts.append("Esc: exit")
			render_console.print(f"\n[gray42]  {'  •  '.join(parts)}[/]")
		render_console.print(f"[dim]{'─' * w}[/]")
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

		if not sys.stdin.isatty():
			return None

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

				elif key == 'space' and self.in_input_mode:
					self.typed += ' '

				elif key == 'space' and not self.in_input_mode:
					opt = self.options[self.selected]
					if opt.get("selectable"):
						if self.selected in self.checked:
							self.checked.discard(self.selected)
						else:
							self.checked.add(self.selected)

				elif key == 'enter':
					# Multi-select: return checked indices if any
					if self.checked:
						self._clear_and_exit(prev_output)
						return (sorted(self.checked), self.typed.strip() if self.typed.strip() else None)
					opt = self.options[self.selected]
					if opt.get("input") and not self.in_input_mode:
						# Enter always confirms immediately; use Tab to edit
						self._clear_and_exit(prev_output)
						return (self.selected, None)
					elif opt.get("input") and self.in_input_mode:
						self._clear_and_exit(prev_output)
						if self.typed.strip():
							return (self.selected, self.typed.strip())
						return (self.selected, None)
					else:
						self._clear_and_exit(prev_output)
						return (self.selected, None)

				elif key == 'tab' and not self.in_input_mode:
					opt = self.options[self.selected]
					if opt.get("input"):
						self.in_input_mode = True
						self.typed = f"{opt['label']}, "

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
				value = getattr(item, key, '')
				value = FORMATTERS.get(key, lambda x: x)(value)
				if isinstance(value, dict) or isinstance(value, list):
					value = yaml.dump(value)
				elif isinstance(value, int) or isinstance(value, float):
					value = str(value)
				values.append(value)
		else:
			values = [item]
		table.add_row(*values)
	return table
