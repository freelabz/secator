"""System clipboard routing for the TUI copy: OSC 52 wrapping and native backend choice.

Subprocess and the environment are mocked; real clipboard behaviour depends on the
terminal / display and needs a hands-on check.
"""
import base64
import subprocess
from unittest import mock

from secator.tui import clipboard


def _which(*present):
	return lambda name: f"/usr/bin/{name}" if name in present else None


def _b64(text):
	return base64.b64encode(text.encode()).decode()


# ---- OSC 52 ----

def test_osc52_plain_terminal():
	assert clipboard.osc52_sequences("héllo", env={}) == [f"\x1b]52;c;{_b64('héllo')}\a"]


def test_osc52_tmux_sends_bare_and_passthrough():
	bare, wrapped = clipboard.osc52_sequences("hi", env={"TMUX": "/tmp/tmux-0/default,1,0"})
	assert bare == f"\x1b]52;c;{_b64('hi')}\a"
	assert wrapped == f"\x1bPtmux;\x1b\x1b]52;c;{_b64('hi')}\a\x1b\\"


def test_osc52_screen_wraps_in_dcs_chunks():
	text = "x" * 500
	(seq,) = clipboard.osc52_sequences(text, env={"STY": "123.pts-0.host"})
	assert seq.startswith("\x1bP\x1b]52;c;") and seq.endswith("\x1b\\")
	chunks = seq.split("\x1b\\")[:-1]
	assert len(chunks) > 1
	assert all(c.startswith("\x1bP") and len(c) - 2 <= clipboard.SCREEN_CHUNK for c in chunks)
	assert "".join(c[2:] for c in chunks) == f"\x1b]52;c;{_b64(text)}\a"


# ---- backend selection ----

def _argvs(backends):
	return [b[0] for b in backends]


def test_no_display_no_backend():
	# e.g. inside a container: only OSC 52 can reach the terminal
	with mock.patch.object(clipboard, "_is_wsl", return_value=False):
		assert clipboard.native_backends(env={}, platform="linux", which=_which("xclip", "wl-copy")) == []


def test_wayland_prefers_wl_copy_then_x():
	env = {"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}
	with mock.patch.object(clipboard, "_is_wsl", return_value=False):
		b = clipboard.native_backends(env=env, platform="linux", which=_which("wl-copy", "xclip"))
	assert _argvs(b) == [["wl-copy"], ["xclip", "-selection", "clipboard"]]
	assert b[0][2] == ["wl-copy", "--primary"]


def test_x11_xclip_and_xsel():
	with mock.patch.object(clipboard, "_is_wsl", return_value=False):
		b = clipboard.native_backends(env={"DISPLAY": ":0"}, platform="linux", which=_which("xclip", "xsel", "wl-copy"))
	assert _argvs(b) == [["xclip", "-selection", "clipboard"], ["xsel", "-b", "-i"]]


def test_tool_missing_is_skipped():
	with mock.patch.object(clipboard, "_is_wsl", return_value=False):
		assert clipboard.native_backends(env={"DISPLAY": ":0"}, platform="linux", which=_which()) == []


def test_macos_pbcopy():
	b = clipboard.native_backends(env={"DISPLAY": ":0"}, platform="darwin", which=_which("pbcopy", "xclip"))
	assert _argvs(b) == [["pbcopy"]]


def test_windows_and_wsl_clip_exe():
	b = clipboard.native_backends(env={}, platform="win32", which=_which("clip.exe"))
	assert b == [(["clip.exe"], "utf-16-le", None)]
	b = clipboard.native_backends(env={"WSL_DISTRO_NAME": "Ubuntu"}, platform="linux", which=_which("clip.exe"))
	assert _argvs(b) == [["clip.exe"]]


# ---- copy_native ----

def test_copy_native_runs_without_shell_with_timeout_and_sets_primary():
	ok = subprocess.CompletedProcess([], 0)
	no_wsl = mock.patch.object(clipboard, "_is_wsl", return_value=False)
	with no_wsl, mock.patch.object(clipboard.subprocess, "run", return_value=ok) as run:
		assert clipboard.copy_native("hi", env={"DISPLAY": ":0"}, platform="linux", which=_which("xclip"))
	assert [c.args[0] for c in run.call_args_list] == [
		["xclip", "-selection", "clipboard"], ["xclip", "-selection", "primary"]]
	kw = run.call_args_list[0].kwargs
	assert kw["input"] == b"hi" and kw["timeout"] == clipboard.NATIVE_TIMEOUT
	assert kw["stdout"] is subprocess.DEVNULL and kw["stderr"] is subprocess.DEVNULL
	assert "shell" not in kw


def test_copy_native_falls_through_failures():
	def run(argv, **kw):
		if argv[0] == "xclip":
			raise subprocess.TimeoutExpired(argv, 2)
		return subprocess.CompletedProcess(argv, 0)
	no_wsl = mock.patch.object(clipboard, "_is_wsl", return_value=False)
	with no_wsl, mock.patch.object(clipboard.subprocess, "run", side_effect=run) as r:
		assert clipboard.copy_native("hi", env={"DISPLAY": ":0"}, platform="linux", which=_which("xclip", "xsel"))
	assert r.call_args_list[1].args[0] == ["xsel", "-b", "-i"]


def test_copy_native_all_fail_returns_false():
	no_wsl = mock.patch.object(clipboard, "_is_wsl", return_value=False)
	with no_wsl, mock.patch.object(clipboard.subprocess, "run", side_effect=OSError("boom")):
		assert not clipboard.copy_native("hi", env={"DISPLAY": ":0"}, platform="linux", which=_which("xclip"))
	assert not clipboard.copy_native("hi", env={}, platform="darwin", which=_which())


def test_clip_exe_gets_utf16():
	with mock.patch.object(clipboard.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
		clipboard.copy_native("é", env={}, platform="win32", which=_which("clip.exe"))
	assert run.call_args.kwargs["input"] == "é".encode("utf-16-le")
