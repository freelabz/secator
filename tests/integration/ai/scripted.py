"""A scripted LLM for end-to-end tests of the ``ai`` task: no real model is ever called.

The ``ai`` task reaches the model through ``litellm.completion`` (``secator.ai.utils.call_llm``)
and prices a call with ``litellm.completion_cost``. :class:`ScriptedModel` replaces both and
replays a list of turns per *scenario*:

* a turn is a :class:`Turn` (text and/or tool calls, several calls run as one batch, or a raw
malformed ``arguments`` payload), or a callable ``f(request) -> Turn`` that branches on what
the model was sent (tool results, background status, ...);
* the scenario of a request is the ``[scenario:<tag>]`` marker in its first user message, so one
model serves a parent run and every subagent it spawns (each subagent objective carries its
own tag), in-process or inside a Celery worker;
* every request is recorded (messages, tool names, time) so a test asserts on what the model was
told; a worker records them to a JSONL file the test reads back;
* usage and cost are filled so token/cost accounting works.

Requests without tools (intent detection, history summarization) are side calls answered by
``side_reply``. A scenario that runs out of turns gets a plain "done" reply and the overrun is
recorded, so a test can fail on it instead of hanging.
"""
import contextlib
import copy
import itertools
import json
import re
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Union
from unittest import mock

SCENARIO_RE = re.compile(r'\[scenario:([\w.@\-]+)\]')
DEFAULT_TAG = '_default'
_IDS = itertools.count(1)


# ---------------------------------------------------------------------------
# Turns
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
	name: str
	args: Dict = field(default_factory=dict)
	raw: Optional[str] = None  # sent verbatim as `arguments` (malformed JSON, wrong shape, ...)
	id: str = ''

	def __post_init__(self):
		if not self.id:
			self.id = f'call_{next(_IDS)}'

	@property
	def arguments(self) -> str:
		return self.raw if self.raw is not None else json.dumps(self.args)


@dataclass
class Turn:
	content: str = ''
	calls: List[ToolCall] = field(default_factory=list)
	finish_reason: Optional[str] = None
	prompt_tokens: int = 1000
	completion_tokens: int = 50
	cost: float = 0.001
	delay: float = 0.0  # seconds the "model" thinks before answering


def call(tool, /, *, id='', **args) -> ToolCall:
	"""One tool call; ``id`` lets a later turn reference its result."""
	return ToolCall(name=tool, args=args, id=id)


def raw_call(tool, raw, /, *, id='') -> ToolCall:
	"""A tool call whose ``arguments`` string is sent as-is (e.g. malformed JSON)."""
	return ToolCall(name=tool, raw=raw, id=id)


def say(text, **kw) -> Turn:
	"""A content-only turn (ends the turn: a non-interactive run then ends)."""
	return Turn(content=text, **kw)


def tools(*calls, content='', **kw) -> Turn:
	"""A turn made of one or several (parallel) tool calls."""
	return Turn(content=content, calls=list(calls), **kw)


def stop(reason='done', **kw) -> Turn:
	return tools(call('stop', reason=reason), **kw)


TurnLike = Union[Turn, Callable[['Request'], Turn]]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

@dataclass
class Request:
	"""One completion request the ai task sent to the model."""
	messages: List[Dict]
	tools: List[str]
	model: str
	tag: str
	index: int  # position within its scenario (0 = first request)
	t: float  # time.monotonic() when received
	side: bool = False
	reply: Optional[Dict] = None  # what the model answered (content + calls)

	# -- tool results -------------------------------------------------------
	def tool_messages(self) -> List[Dict]:
		return [m for m in self.messages if m.get('role') == 'tool']

	def tool_result(self, tool_call_id) -> Optional[str]:
		"""Content of the tool result answering ``tool_call_id`` (None if not answered yet)."""
		for m in self.messages:
			if m.get('role') == 'tool' and m.get('tool_call_id') == tool_call_id:
				return m.get('content') or ''
		return None

	def tool_json(self, tool_call_id) -> Any:
		"""The tool result parsed as JSON (``<workspace_data>`` envelope and hints stripped)."""
		return parse_tool_result(self.tool_result(tool_call_id))

	def new_tool_messages(self, previous: Optional['Request']) -> List[Dict]:
		"""Tool results added since ``previous`` (the results of the last turn's calls)."""
		seen = {m.get('tool_call_id') for m in (previous.tool_messages() if previous else [])}
		return [m for m in self.tool_messages() if m.get('tool_call_id') not in seen]

	# -- text helpers -------------------------------------------------------
	def last_user(self) -> str:
		for m in reversed(self.messages):
			if m.get('role') == 'user':
				return m.get('content') or ''
		return ''

	def text(self) -> str:
		"""Every message content concatenated (for coarse ``in`` assertions)."""
		parts = []
		for m in self.messages:
			parts.append(str(m.get('content') or ''))
			for tc in m.get('tool_calls') or []:
				parts.append(json.dumps(tc))
		return '\n'.join(parts)

	def find(self, pattern, last=True) -> Optional[str]:
		found = re.findall(pattern, self.text())
		if not found:
			return None
		return found[-1] if last else found[0]

	def to_dict(self):
		return {
			'messages': self.messages, 'tools': self.tools, 'model': self.model, 'tag': self.tag,
			'index': self.index, 't': self.t, 'side': self.side, 'reply': self.reply,
		}

	@classmethod
	def from_dict(cls, d):
		return cls(**d)


def parse_tool_result(content) -> Any:
	"""Parse a tool result string into JSON when it holds one; return the raw string otherwise."""
	if content is None:
		return None
	text = content.strip()
	m = re.match(r'<workspace_data>\s*(.*?)\s*</workspace_data>', text, re.DOTALL)
	if m:
		text = m.group(1)
	try:
		return json.loads(text)
	except (ValueError, TypeError):
		pass
	# A trailing hint line follows the JSON body: decode the first JSON value only.
	try:
		obj, _ = json.JSONDecoder().raw_decode(text)
		return obj
	except (ValueError, TypeError):
		return content


def load_requests(path) -> List[Request]:
	"""Read the requests a worker-side model recorded (JSONL)."""
	out = []
	try:
		with open(path) as f:
			for line in f:
				line = line.strip()
				if line:
					out.append(Request.from_dict(json.loads(line)))
	except FileNotFoundError:
		pass
	return out


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------

def _scenario_tag(messages) -> str:
	for m in messages:
		if m.get('role') == 'user':
			found = SCENARIO_RE.search(str(m.get('content') or ''))
			return found.group(1) if found else DEFAULT_TAG
	return DEFAULT_TAG


def _default_side_reply(request: Request) -> str:
	text = request.last_user().lower()
	if 'summar' in text:
		return 'Summary: the earlier conversation ran tools against the local lab targets.'
	return 'scan'


class ScriptedModel:
	"""Replays scripted turns per scenario and records every request (thread-safe)."""

	def __init__(self, record_path=None, scenario_factory: Optional[Callable[[str], List[TurnLike]]] = None):
		self._lock = threading.RLock()
		self._scripts: Dict[str, List[TurnLike]] = {}
		self._cursor: Dict[str, int] = {}
		self.requests: List[Request] = []
		self.overruns: List[str] = []
		self.side_reply: Callable[[Request], str] = _default_side_reply
		self.record_path = record_path
		self.scenario_factory = scenario_factory  # worker side: build a scenario from its tag

	# -- scripting ----------------------------------------------------------
	def script(self, turns: List[TurnLike], tag: str = DEFAULT_TAG):
		with self._lock:
			self._scripts[tag] = list(turns)
			self._cursor[tag] = 0

	def for_tag(self, tag: str, side: bool = False) -> List[Request]:
		with self._lock:
			return [r for r in self.requests if r.tag == tag and r.side == side]

	def remaining(self, tag: str = DEFAULT_TAG) -> int:
		with self._lock:
			return len(self._scripts.get(tag, [])) - self._cursor.get(tag, 0)

	# -- litellm entry points ----------------------------------------------
	def completion(self, model=None, messages=None, tools=None, **kwargs):
		messages = copy.deepcopy(messages or [])
		tag = _scenario_tag(messages)
		side = not tools
		with self._lock:
			if tag not in self._scripts and self.scenario_factory is not None and not side:
				self.script(self.scenario_factory(tag), tag=tag)
			index = len([r for r in self.requests if r.tag == tag and r.side == side])
			req = Request(
				messages=messages, tools=sorted(t['function']['name'] for t in (tools or [])),
				model=model, tag=tag, index=index, t=time.monotonic(), side=side)
			self.requests.append(req)
			if side:
				turn = Turn(content=self.side_reply(req))
			else:
				script = self._scripts.get(tag)
				pos = self._cursor.get(tag, 0)
				if script is None or pos >= len(script):
					self.overruns.append(tag)
					turn = Turn(content='(script exhausted) done')
				else:
					self._cursor[tag] = pos + 1
					turn = script[pos]
		if callable(turn):
			turn = turn(req)
		if isinstance(turn, ToolCall):
			turn = tools(turn)
		if isinstance(turn, str):
			turn = say(turn)
		if turn.delay:
			time.sleep(turn.delay)
		req.reply = {'content': turn.content, 'calls': [
			{'id': c.id, 'name': c.name, 'arguments': c.arguments} for c in turn.calls]}
		self._record(req)
		return self._response(model, turn)

	def completion_cost(self, completion_response=None, **kwargs):
		return getattr(completion_response, '_scripted_cost', 0.0)

	@staticmethod
	def _response(model, turn: Turn):
		tool_calls = [
			SimpleNamespace(id=c.id, type='function', function=SimpleNamespace(name=c.name, arguments=c.arguments))
			for c in turn.calls
		] or None
		message = SimpleNamespace(role='assistant', content=turn.content or None, tool_calls=tool_calls)
		finish = turn.finish_reason or ('tool_calls' if tool_calls else 'stop')
		usage = SimpleNamespace(
			total_tokens=turn.prompt_tokens + turn.completion_tokens,
			prompt_tokens=turn.prompt_tokens, completion_tokens=turn.completion_tokens)
		resp = SimpleNamespace(
			id=f'scripted-{next(_IDS)}', model=model,
			choices=[SimpleNamespace(index=0, message=message, finish_reason=finish)], usage=usage)
		resp._scripted_cost = turn.cost
		return resp

	def _record(self, req: Request):
		if not self.record_path:
			return
		with self._lock, open(self.record_path, 'a') as f:
			f.write(json.dumps(req.to_dict(), default=str) + '\n')

	# -- install ------------------------------------------------------------
	@contextlib.contextmanager
	def installed(self):
		"""Patch litellm so this model is the only one the ai task can reach."""
		patchers = self.patchers()
		for p in patchers:
			p.start()
		try:
			yield self
		finally:
			for p in reversed(patchers):
				p.stop()

	def patchers(self):
		import litellm
		return [
			mock.patch.object(litellm, 'completion', self.completion),
			mock.patch.object(litellm, 'completion_cost', self.completion_cost),
			# Anything that reaches the async / text-completion entry points is a bug in the
			# test setup: fail loudly instead of calling a real provider.
			mock.patch.object(litellm, 'acompletion', _forbidden('litellm.acompletion')),
			mock.patch.object(litellm, 'text_completion', _forbidden('litellm.text_completion')),
		]


def _forbidden(name):
	def _raise(*a, **kw):
		raise AssertionError(f'{name} called during a scripted-model test')
	return _raise


# ---------------------------------------------------------------------------
# Network guard
# ---------------------------------------------------------------------------

def _is_loopback(host) -> bool:
	"""A loopback IP (127.0.0.0/8, ::1) or exactly ``localhost``; nothing matched by prefix."""
	host = str(host)
	if host == 'localhost':
		return True
	try:
		return ipaddress.ip_address(host.split('%', 1)[0]).is_loopback
	except ValueError:
		return False


class NetworkGuard:
	"""Block every outbound connection of THIS Python process except loopback and unix sockets;
	record attempts. Child processes (shell commands, tool binaries) are not covered: scenarios
	only point them at the local lab, or at targets the scope check denies before they run."""

	def __init__(self, on_block: Optional[Callable[[str], None]] = None):
		self.blocked: List[str] = []
		self.on_block = on_block
		self._orig_connect = socket.socket.connect
		self._orig_connect_ex = socket.socket.connect_ex

	def _allowed(self, sock, address) -> bool:
		if sock.family == getattr(socket, 'AF_UNIX', None):
			return True
		host = address[0] if isinstance(address, tuple) else str(address)
		return _is_loopback(host)

	def _block(self, address):
		self.blocked.append(repr(address))
		if self.on_block is not None:
			self.on_block(repr(address))

	def start(self):
		guard = self

		def connect(sock, address):
			if not guard._allowed(sock, address):
				guard._block(address)
				raise ConnectionRefusedError(f'network blocked in AI e2e tests: {address!r}')
			return guard._orig_connect(sock, address)

		def connect_ex(sock, address):
			if not guard._allowed(sock, address):
				guard._block(address)
				return 111  # ECONNREFUSED
			return guard._orig_connect_ex(sock, address)

		socket.socket.connect = connect
		socket.socket.connect_ex = connect_ex
		return self

	def stop(self):
		socket.socket.connect = self._orig_connect
		socket.socket.connect_ex = self._orig_connect_ex
