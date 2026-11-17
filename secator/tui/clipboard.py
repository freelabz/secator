"""System clipboard helpers for the secator TUI.

Textual's ``App.copy_to_clipboard`` only stores the text in the app (``app.clipboard``,
which in-app paste reads) and writes a bare OSC 52 escape to the terminal. Many setups
drop that escape: terminals without OSC 52 support (or with it disabled by default),
tmux / GNU screen (which swallow it unless it is wrapped or explicitly allowed), size
caps. When that happens the copy never leaves the app.

This module makes the copy reach the outside world through every route available:
- an OSC 52 sequence, wrapped for tmux (DCS passthrough) or screen when running inside
	one of them;
- a native clipboard command when one is reachable (``wl-copy``, ``xclip`` / ``xsel``,
	``pbcopy``, ``clip.exe``), plus the X / Wayland PRIMARY selection (middle-click paste).

Pure stdlib, no Textual import, so it is unit-testable on its own.
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys

NATIVE_TIMEOUT = 2  # seconds; a clipboard command should be near-instant
SCREEN_CHUNK = 76  # GNU screen caps a DCS string (~768 bytes): split the payload


def _osc52(text: str) -> str:
	b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
	return f"\x1b]52;c;{b64}\a"


def osc52_sequences(text: str, env=None) -> list:
	"""The escape sequence(s) to write to the terminal to set its clipboard to ``text``.

	- plain terminal: the bare OSC 52;
	- tmux (``TMUX``): the bare OSC 52 (honoured with ``set-clipboard on``) AND a DCS
	  passthrough-wrapped copy (honoured with ``allow-passthrough on``) — whichever the
	  user's tmux accepts, the other is dropped;
	- GNU screen (``STY``): the OSC 52 wrapped in DCS, split into chunks.
	"""
	env = os.environ if env is None else env
	seq = _osc52(text)
	if env.get("TMUX"):
		# DCS passthrough: every ESC inside the payload is doubled
		return [seq, "\x1bPtmux;" + seq.replace("\x1b", "\x1b\x1b") + "\x1b\\"]
	if env.get("STY"):
		chunks = [seq[i:i + SCREEN_CHUNK] for i in range(0, len(seq), SCREEN_CHUNK)]
		return ["".join(f"\x1bP{c}\x1b\\" for c in chunks)]
	return [seq]


def _is_wsl(env) -> bool:
	if env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
		return True
	try:
		with open("/proc/version", encoding="utf-8") as f:
			return "microsoft" in f.read().lower()
	except OSError:
		return False


def native_backends(env=None, platform=None, which=shutil.which) -> list:
	"""Native clipboard commands to try, in order, as ``(argv, encoding, primary_argv)``.

	``primary_argv`` (or None) also sets the X / Wayland PRIMARY selection so middle-click
	paste works. Only commands that are installed and whose display is reachable are listed.
	"""
	env = os.environ if env is None else env
	platform = sys.platform if platform is None else platform
	out = []
	if platform == "darwin":
		if which("pbcopy"):
			out.append((["pbcopy"], "utf-8", None))
		return out
	if platform.startswith("win"):
		if which("clip.exe") or which("clip"):
			out.append((["clip.exe"], "utf-16-le", None))
		return out
	if env.get("WAYLAND_DISPLAY") and which("wl-copy"):
		out.append((["wl-copy"], "utf-8", ["wl-copy", "--primary"]))
	if env.get("DISPLAY"):
		if which("xclip"):
			out.append((["xclip", "-selection", "clipboard"], "utf-8", ["xclip", "-selection", "primary"]))
		if which("xsel"):
			out.append((["xsel", "-b", "-i"], "utf-8", ["xsel", "-p", "-i"]))
	if _is_wsl(env) and which("clip.exe"):
		out.append((["clip.exe"], "utf-16-le", None))
	return out


def _run(argv, data: bytes) -> bool:
	try:
		# stdout/stderr to DEVNULL (not pipes): xclip / wl-copy fork a child that keeps
		# serving the selection; a pipe would make run() wait for that child until timeout.
		devnull = subprocess.DEVNULL
		proc = subprocess.run(argv, input=data, stdout=devnull, stderr=devnull, timeout=NATIVE_TIMEOUT, check=False)
		return proc.returncode == 0
	except (OSError, subprocess.SubprocessError, ValueError):
		return False


def copy_native(text: str, env=None, platform=None, which=shutil.which) -> bool:
	"""Copy ``text`` with the first native clipboard command that succeeds (and best-effort
	the PRIMARY selection). Returns True if the system clipboard was set. Never raises."""
	for argv, encoding, primary in native_backends(env, platform, which):
		data = text.encode(encoding)
		if _run(argv, data):
			if primary:
				_run(primary, data)
			return True
	return False
