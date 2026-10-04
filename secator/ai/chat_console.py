"""Rich-native always-on chat input for the local AI runner (Option B).

A single rich ``Live`` is pinned at the bottom of the terminal showing a status
line (the AI's current activity, animated) and an input box, framed by rules with
the session name. Streamed findings/output scroll ABOVE it (rich renders console
writes above an active Live). Because ``maybe_status`` no-ops while a Live is
active, every ``console.status`` spinner in the codebase auto-suppresses and its
message is surfaced in this one status line instead — so the status keeps working
without a second Live fighting for the terminal.

A background thread reads keys in cbreak mode and edits the input buffer; a
submitted line goes to a queue that the AI loop drains (mid-flight steer) or waits
on (end-of-turn). Raw-mode menus (permission / multi-choice follow-up) call
``pause()``/``resume()`` so they briefly own the terminal.

Untested interactively in CI — needs a real TTY.
"""
import queue
import threading
import time

from secator.rich import console

EXIT = '\x00__exit__'


class _ChatRenderable:
	"""Live renderable: reads the ChatConsole's current state each refresh."""

	def __init__(self, chat):
		self.chat = chat

	def __rich__(self):
		from rich.console import Group
		from rich.rule import Rule
		from rich.text import Text
		from rich.spinner import Spinner

		c = self.chat
		rows = [Rule(title=c.session_name, characters='─', style='dim')]
		if c.status:
			rows.append(Spinner('dots', text=Text(c.status, style='gold3')))
		cursor = '█' if (time.time() * 2) % 2 < 1 else ' '
		rows.append(Text.assemble(('› ', 'bold cyan'), (c.buffer, 'white'), (cursor, 'dim')))
		rows.append(Rule(characters='─', style='dim'))
		return Group(*rows)


class ChatConsole:

	def __init__(self, session_name=''):
		self.session_name = (session_name or 'ai')[:30]
		self.buffer = ''
		self.status = ''
		self._q = queue.Queue()
		self._live = None
		self._reader = None
		self._stop = None
		self._paused = None
		self._fd = None
		self._old_termios = None
		self._active = False

	@property
	def active(self):
		return self._active

	# -- lifecycle --
	def start(self):
		import sys
		from secator.definitions import IN_WORKER
		if self._active or IN_WORKER:
			return
		if not getattr(sys, 'stdin', None) or not sys.stdin.isatty():
			return
		self._fd = sys.stdin.fileno()
		self._stop = threading.Event()
		self._paused = threading.Event()
		self._active = True
		self._enter_cbreak()
		self._start_live()
		self._reader = threading.Thread(target=self._read_loop, daemon=True)
		self._reader.start()

	def stop(self):
		if not self._active:
			return
		self._active = False
		self._stop.set()
		self._stop_live()
		self._restore_termios()

	def _enter_cbreak(self):
		import termios
		import tty
		try:
			self._old_termios = termios.tcgetattr(self._fd)
			tty.setcbreak(self._fd)  # char-at-a-time, no echo, but keep OPOST (newlines work)
		except Exception:
			self._old_termios = None

	def _restore_termios(self):
		import termios
		if self._old_termios is not None:
			try:
				termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_termios)
			except Exception:
				pass
			self._old_termios = None

	def _start_live(self):
		from rich.live import Live
		self._live = Live(
			_ChatRenderable(self), console=console, auto_refresh=True,
			refresh_per_second=12.5, transient=True,
		)
		self._live.start()

	def _stop_live(self):
		if self._live is not None:
			try:
				self._live.stop()
			except Exception:
				pass
			self._live = None

	# -- pause/resume around a raw-mode menu (it owns the terminal briefly) --
	def pause(self):
		if not self._active:
			return
		self._paused.set()
		self._stop_live()
		self._restore_termios()
		time.sleep(0.05)

	def resume(self):
		if not self._active:
			return
		self._enter_cbreak()
		self._start_live()
		self._paused.clear()

	# -- input reading --
	def _read_loop(self):
		import os
		import select
		while not self._stop.is_set():
			if self._paused.is_set():
				time.sleep(0.05)
				continue
			try:
				r, _, _ = select.select([self._fd], [], [], 0.2)
			except (OSError, ValueError):
				return
			if not r or self._paused.is_set():
				continue
			try:
				ch = os.read(self._fd, 1).decode('utf-8', 'ignore')
			except Exception:
				continue
			if ch == '':
				continue
			self._handle_char(ch)
			if self._live is not None:
				try:
					self._live.refresh()
				except Exception:
					pass

	def _handle_char(self, ch):
		if ch in ('\x03', '\x04'):  # Ctrl-C / Ctrl-D
			self._q.put(EXIT)
			return
		if ch in ('\r', '\n'):
			line = self.buffer.strip()
			self.buffer = ''
			if line:
				# Echo the sent message above the box so it isn't "stuck" in the input.
				try:
					console.print(f'[cyan]›[/] {line}')
				except Exception:
					pass
				self._q.put(line)
			return
		if ch in ('\x7f', '\x08'):  # backspace
			self.buffer = self.buffer[:-1]
			return
		if ch == '\x1b':  # swallow escape sequences (arrows etc.) — read & drop the rest
			import select
			try:
				while select.select([self._fd], [], [], 0.005)[0]:
					import os
					os.read(self._fd, 1)
			except Exception:
				pass
			return
		if ch.isprintable():
			self.buffer += ch

	# -- status (driven by maybe_status reroute) --
	def set_status(self, msg):
		self.status = msg or ''

	def clear_status(self):
		self.status = ''

	# -- queue access for the AI loop --
	def poll_steers(self):
		"""Drain lines typed since the last poll (mid-flight)."""
		out = []
		while True:
			try:
				out.append(self._q.get_nowait())
			except queue.Empty:
				break
		return out

	def wait_line(self, timeout=None):
		"""Block for the next submitted line (end-of-turn)."""
		try:
			return self._q.get(timeout=timeout)
		except queue.Empty:
			return None


# Process-wide handle so maybe_status() can surface its message in the chat status
# line instead of starting a competing Live.
_ACTIVE = None


def set_active(chat):
	global _ACTIVE
	_ACTIVE = chat


def get_active():
	return _ACTIVE
