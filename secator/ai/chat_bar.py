"""Always-on input bar for the local AI runner, via a terminal scroll region.

The terminal's scroll region (DECSTBM) is set to all-but-the-bottom-N lines, so every
existing rich display — findings, ``console.status`` spinners, ``Progress`` bars —
scrolls ABOVE, untouched. The bottom N lines are frozen and we draw the input bar
there with raw escapes. No rich ``Live`` is used for the input, so it coexists with
the one rich ``Live`` the run already uses (no "only one live display" error) and the
status keeps rendering normally above the bar.

A background thread reads keys in cbreak mode and edits the buffer; a submitted line
is echoed above the bar and fed to one queue that the AI loop drains (mid-flight) or
waits on (end-of-turn). Raw-mode menus (permission / multi-choice) call pause()/resume()
to drop the scroll region briefly.

Terminal-fiddly and untestable headlessly — needs a real TTY.
"""
import os
import queue
import shutil
import sys
import threading
import time

from secator.rich import console

EXIT = '\x00__exit__'
N = 3  # reserved bottom lines: top rule (session), input, bottom rule

_DIM = '\x1b[2m'
_CYAN = '\x1b[36m'
_RESET = '\x1b[0m'


class ChatBar:

	def __init__(self, session_name=''):
		self.session_name = (session_name or 'ai')[:30]
		self.buffer = ''
		self._q = queue.Queue()
		self._reader = None
		self._stop = None
		self._paused = None
		self._fd = None
		self._old_termios = None
		self._tty = None
		self._lock = threading.Lock()
		self._active = False

	@property
	def active(self):
		return self._active

	# -- lifecycle --
	def start(self):
		from secator.definitions import IN_WORKER
		if self._active or IN_WORKER:
			return
		if not getattr(sys, 'stdin', None) or not sys.stdin.isatty():
			return
		self._fd = sys.stdin.fileno()
		try:
			self._tty = open('/dev/tty', 'w')
		except Exception:
			self._tty = sys.stderr
		self._stop = threading.Event()
		self._paused = threading.Event()
		self._active = True
		self._enter_cbreak()
		self._install_region()
		self._reader = threading.Thread(target=self._read_loop, daemon=True)
		self._reader.start()

	def stop(self):
		if not self._active:
			return
		self._active = False
		self._stop.set()
		self._remove_region()
		self._restore_termios()
		if self._tty is not None and self._tty is not sys.stderr:
			try:
				self._tty.close()
			except Exception:
				pass

	# -- terminal mode --
	def _enter_cbreak(self):
		import termios
		import tty
		try:
			self._old_termios = termios.tcgetattr(self._fd)
			tty.setcbreak(self._fd)
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

	# -- low-level writes (one locked write per call keeps sequences atomic-ish) --
	def _emit(self, seq):
		with self._lock:
			try:
				self._tty.write(seq)
				self._tty.flush()
			except Exception:
				pass

	def _size(self):
		sz = shutil.get_terminal_size((80, 24))
		return sz.columns, sz.lines

	def _install_region(self):
		cols, rows = self._size()
		# Push existing content up by N lines (so we don't overwrite it), set the
		# scroll region above the bar, park the cursor at the bottom of that region,
		# then draw the bar.
		self._emit('\n' * N + f'\x1b[1;{rows - N}r' + f'\x1b[{rows - N};1H')
		self._draw(cols, rows)

	def _remove_region(self):
		cols, rows = self._size()
		seq = '\x1b[r'  # reset scroll region to full screen
		seq += f'\x1b[{rows - N + 1};1H'
		for _ in range(N):  # clear the bar lines
			seq += '\x1b[2K\x1b[1B'
		self._emit(seq)

	def _draw(self, cols=None, rows=None):
		if cols is None:
			cols, rows = self._size()
		top = rows - N + 1
		name = f' {self.session_name} '
		left = max(0, (cols - len(name)) // 2)
		rule_top = '─' * left + name + '─' * max(0, cols - left - len(name))
		rule_bot = '─' * cols
		prompt = '› '
		avail = max(1, cols - len(prompt) - 1)
		shown = self.buffer[-avail:]
		seq = (
			'\x1b7\x1b[?25l'
			+ f'\x1b[{top};1H\x1b[2K' + _DIM + rule_top + _RESET
			+ f'\x1b[{top + 1};1H\x1b[2K' + _CYAN + prompt + _RESET + shown
			+ f'\x1b[{top + 2};1H\x1b[2K' + _DIM + rule_bot + _RESET
			+ '\x1b[?25h\x1b8'
		)
		self._emit(seq)

	def redraw(self):
		if self._active and not self._paused.is_set():
			self._draw()

	# -- pause/resume around a raw-mode menu --
	def pause(self):
		if not self._active:
			return
		self._paused.set()
		self._remove_region()
		time.sleep(0.05)

	def resume(self):
		if not self._active:
			return
		self._install_region()
		self._paused.clear()

	# -- input reading --
	def _read_loop(self):
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
			self.redraw()

	def _handle_char(self, ch):
		if ch in ('\x03', '\x04'):  # Ctrl-C / Ctrl-D
			self._q.put(EXIT)
			return
		if ch in ('\r', '\n'):
			line = self.buffer.strip()
			self.buffer = ''
			if line:
				self._echo(line)
				self._q.put(line)
			return
		if ch in ('\x7f', '\x08'):  # backspace
			self.buffer = self.buffer[:-1]
			return
		if ch == '\x1b':  # drop escape sequences (arrows etc.)
			import select
			try:
				while select.select([self._fd], [], [], 0.005)[0]:
					os.read(self._fd, 1)
			except Exception:
				pass
			return
		if ch.isprintable():
			self.buffer += ch

	def _echo(self, line):
		"""Print the submitted message into the scroll region (above the bar)."""
		try:
			console.print(f'[cyan]›[/] {line}')
		except Exception:
			pass

	# -- queue access --
	def poll_steers(self):
		out = []
		while True:
			try:
				out.append(self._q.get_nowait())
			except queue.Empty:
				break
		return out

	def wait_line(self, timeout=None):
		try:
			return self._q.get(timeout=timeout)
		except queue.Empty:
			return None
