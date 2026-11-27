"""Shared fixtures for the ai task end-to-end scenarios (scripted model, local lab, run helper).

Everything runs against 127.0.0.1 only: a small HTTP lab (two ports, a slow endpoint), a
workspace + reports dir in a temp folder, and a :class:`ScriptedModel` patched in at the
``litellm.completion`` boundary. Outbound network is blocked for the whole test (loopback and
unix sockets excepted), so a stray real model call fails the test instead of reaching a provider.
"""
import os

# litellm fetches its model cost map over the network at import unless told to use the bundled
# copy. Set before anything imports it.
os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')

import glob  # noqa: E402
import json  # noqa: E402
import signal  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from dataclasses import dataclass, field  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, Dict, List  # noqa: E402
from urllib.parse import parse_qs, urlparse  # noqa: E402

import pytest  # noqa: E402

from secator.definitions import ADDONS_ENABLED  # noqa: E402

from tests.integration.ai.scripted import NetworkGuard, ScriptedModel, parse_tool_result  # noqa: E402

if not ADDONS_ENABLED.get('ai'):
	pytest.skip('ai addon (litellm) not installed', allow_module_level=True)

MODEL = 'gpt-4o-mini'  # in litellm's bundled registry: known context window, no network lookup
from tests.integration.ai.worker_config import EXTRA_ALLOW  # noqa: E402
LOG_FORBIDDEN = ('Traceback (most recent call last)', 'Never call result.get()')


DEFAULT_TIMEOUT = 240  # seconds per test: a wedged run fails instead of hanging the job


def pytest_configure(config):
	config.addinivalue_line('markers', 'ai_timeout(seconds): per-test timeout of an ai e2e scenario')
	config.addinivalue_line('markers', 'slow: ai e2e scenario that takes minutes (opt-in: SECATOR_TEST_AI_SLOW=1)')
	config.addinivalue_line('markers', 'worker: ai e2e scenario that needs a real Celery worker')


def pytest_collection_modifyitems(config, items):
	"""Slow scenarios (real Celery workers, the ~2 min polling loop) run only when asked:
	SECATOR_TEST_AI_SLOW=1 (set in CI), so a local run of the suite stays a few minutes."""
	if os.environ.get('SECATOR_TEST_AI_SLOW') == '1':
		return
	skip = pytest.mark.skip(reason='slow ai e2e scenario: set SECATOR_TEST_AI_SLOW=1 to run it')
	for item in items:
		if 'slow' in item.keywords and '/integration/ai/' in str(item.fspath):
			item.add_marker(skip)


@pytest.fixture(autouse=True)
def _ai_timeout(request):
	"""Fail a scenario that runs longer than its timeout (SIGALRM: the ai loop runs in this thread)."""
	marker = request.node.get_closest_marker('ai_timeout')
	seconds = int(marker.args[0]) if marker else DEFAULT_TIMEOUT

	def _expired(signum, frame):
		raise TimeoutError(f'ai e2e scenario exceeded {seconds}s')

	previous = signal.signal(signal.SIGALRM, _expired)
	signal.alarm(seconds)
	yield
	signal.alarm(0)
	signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------------------
# Local HTTP lab
# ---------------------------------------------------------------------------

PAGES = {
	'/': (200, '<html><head><title>Lab home</title></head><body><a href="/login">login</a></body></html>'),
	'/login': (200, '<html><head><title>Lab login</title></head><body><form></form></body></html>'),
	'/admin': (403, '<html><head><title>Forbidden</title></head><body>no</body></html>'),
	# Looks like a leaked access key: exercises the secret encryption before the model sees it.
	'/leak': (200, 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n'
	               'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'),
}


class _LabHandler(BaseHTTPRequestHandler):
	def do_GET(self):  # noqa: N802
		url = urlparse(self.path)
		if url.path == '/slow':
			query = parse_qs(url.query)
			delay = float(query.get('s', ['3'])[0])
			start = time.time()
			time.sleep(delay)
			if 'id' in query:  # an id'ed hit records when it was served (overlap checks)
				self.server.hits.setdefault(query['id'][0], []).append((start, time.time()))
			status, body = 200, f'<html><head><title>Slow {delay}</title></head><body>slow</body></html>'
		else:
			status, body = PAGES.get(url.path, (404, '<html><head><title>Not found</title></head></html>'))
		data = body.encode()
		self.send_response(status)
		self.send_header('Content-Type', 'text/html')
		self.send_header('Content-Length', str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def log_message(self, *args):
		pass


class _LabServer(ThreadingHTTPServer):
	daemon_threads = True

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.hits = {}  # /slow?id=<id> -> [(start, end)]

	def handle_error(self, request, client_address):
		pass  # a client hanging up mid-response (timeouts, cancels) is expected here


@dataclass
class Lab:
	port: int
	port2: int
	servers: list = field(default_factory=list, repr=False)

	def hits(self, hit_id):
		"""(start, end) of each /slow?id=<hit_id> request served, on either port."""
		return [h for srv in self.servers for h in srv.hits.get(hit_id, [])]

	@property
	def url(self):
		return f'http://127.0.0.1:{self.port}'

	@property
	def url2(self):
		return f'http://127.0.0.1:{self.port2}'


@pytest.fixture(scope='session')
def lab():
	servers = []
	for _ in range(2):
		srv = _LabServer(('127.0.0.1', 0), _LabHandler)
		threading.Thread(target=srv.serve_forever, daemon=True).start()
		servers.append(srv)
	yield Lab(servers[0].server_address[1], servers[1].server_address[1], servers)
	for srv in servers:
		srv.shutdown()
		srv.server_close()


# ---------------------------------------------------------------------------
# Isolated secator dirs
# ---------------------------------------------------------------------------

@pytest.fixture(scope='package', autouse=True)
def _ai_dirs():
	"""Reports + data dirs in a temp folder (a workspace per run of this package), restored when
	the package is done so the rest of the pytest session is untouched."""
	from secator.config import CONFIG
	# Child commands inherit fd 0: httpx reads an inherited open stdin (a pipe/socket) and waits
	# on it forever. Point it at /dev/null for the session.
	saved_stdin = os.dup(0)
	devnull = os.open(os.devnull, os.O_RDONLY)
	os.dup2(devnull, 0)
	os.close(devnull)
	root = Path(tempfile.mkdtemp(prefix='secator-ai-e2e-'))
	old, old_templates = CONFIG.dirs.reports, CONFIG.dirs.templates
	CONFIG.dirs.reports = root / 'reports'
	CONFIG.dirs.reports.mkdir(parents=True, exist_ok=True)
	CONFIG.dirs.templates = root / 'templates'
	CONFIG.dirs.templates.mkdir(parents=True, exist_ok=True)
	# `sleep` is the scenarios' stand-in for a long-running command; it is not in the default
	# shell allow-list (an unknown command is denied by a non-interactive run).
	allow = CONFIG.addons.ai.permissions['allow']
	allow.append(EXTRA_ALLOW)
	yield root
	allow.remove(EXTRA_ALLOW)
	CONFIG.dirs.reports, CONFIG.dirs.templates = old, old_templates
	from secator import loader  # templates were loaded from the temp dir: forget them
	loader.find_templates.cache_clear()
	loader.get_configs_by_type.cache_clear()
	os.dup2(saved_stdin, 0)
	os.close(saved_stdin)
	import shutil
	shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Scripted model + network guard
# ---------------------------------------------------------------------------

@pytest.fixture
def model():
	"""The scripted model, patched in for the test; fails the test on any non-loopback connect."""
	guard = NetworkGuard().start()
	m = ScriptedModel()
	try:
		with m.installed():
			yield m
	finally:
		guard.stop()
	assert not guard.blocked, f'outbound network attempted: {guard.blocked}'


# ---------------------------------------------------------------------------
# Run helper
# ---------------------------------------------------------------------------

@dataclass
class AiRun:
	task: Any
	items: List[Any]
	requests: List[Any]
	elapsed: float
	log: str = ''
	side_requests: List[Any] = field(default_factory=list)  # requests without tools (summaries)

	@property
	def status(self):
		return self.task.status

	def ai(self, ai_type=None) -> List[Any]:
		return [i for i in self.items if getattr(i, '_type', None) == 'ai'
		        and (ai_type is None or i.ai_type == ai_type)]

	def of_type(self, _type) -> List[Any]:
		return [i for i in self.items if getattr(i, '_type', None) == _type]

	def errors(self) -> List[str]:
		return [i.message for i in self.of_type('error')]

	def warnings(self) -> List[str]:
		return [i.message for i in self.of_type('warning')]

	# -- what the model was told ---------------------------------------------
	def tool_result(self, call_id) -> str:
		"""The tool result the model received for ``call_id`` (first request that carries it)."""
		for r in self.requests:
			res = r.tool_result(call_id)
			if res is not None:
				return res
		raise AssertionError(f'no tool result for {call_id} in {len(self.requests)} request(s)')

	def tool_json(self, call_id):
		return parse_tool_result(self.tool_result(call_id))

	# -- what was persisted (json driver) ------------------------------------
	@property
	def folder(self) -> Path:
		return Path(self.task.reports_folder)

	def children(self, name=None) -> List[Dict]:
		"""Info blocks of the runners this run spawned (see :func:`children_of`)."""
		return children_of(self.task.context.get('session_id'), self.task.id, name=name)

	def stored(self, _type=None) -> List[Dict]:
		"""Every result the run streamed to its results.ndjson (latest record per _uuid)."""
		path = self.folder / 'results.ndjson'
		latest = {}
		if path.exists():
			for line in path.read_text().splitlines():
				try:
					rec = json.loads(line)
				except ValueError:
					continue
				latest[rec.get('_uuid') or id(rec)] = rec
		return [r for r in latest.values() if _type is None or r.get('_type') == _type]


def children_of(session_id, run_id, name=None) -> List[Dict]:
	"""Info blocks of the runners an ai run spawned, subagents' own children included.

	Read from the json driver reports in any folder. A child is matched by the session id it
	inherited (a subagent has its own session, linked by ``parent_session_id``); the ai run's own
	reports (``task_id`` == ``run_id``) are skipped. Each child is read from its own reports
	folder: its ``report.json`` when it is a top-level runner there (a task), else its
	``report_<name>.json`` (a workflow, whose tasks write ``report_<workflow>_<task>.json`` next
	to it). ``_path`` says which file.
	"""
	from secator.config import CONFIG
	infos = []
	for path in glob.glob(str(Path(CONFIG.dirs.reports) / '**' / 'report*.json'), recursive=True):
		try:
			info = json.loads(Path(path).read_text()).get('info', {})
		except (ValueError, OSError):
			continue
		info['_path'] = path
		infos.append(info)
	sessions = {session_id}
	grew = True
	while grew:
		grew = False
		for info in infos:
			ctx = info.get('context') or {}
			if ctx.get('parent_session_id') in sessions and ctx.get('session_id') not in sessions:
				sessions.add(ctx.get('session_id'))
				grew = True
	by_folder = {}
	for info in infos:
		ctx = info.get('context') or {}
		if ctx.get('session_id') not in sessions or ctx.get('task_id') == run_id:
			continue
		by_folder.setdefault(str(Path(info['_path']).parent), []).append(info)
	out = []
	for group in by_folder.values():
		group.sort(key=lambda i: (not i['_path'].endswith('/report.json'), len(i['_path'])))
		top = group[0]
		if name is None or top.get('name') == name:
			out.append(top)
	return out


FINAL_STATUSES = ('SUCCESS', 'FAILURE', 'REVOKED', 'SKIPPED')


def install_workflow(name, body):
	"""Write a workflow template to the session templates dir and reload the template caches."""
	from secator.config import CONFIG
	from secator import loader
	folder = Path(CONFIG.dirs.templates)
	folder.mkdir(parents=True, exist_ok=True)
	(folder / f'{name}.yaml').write_text(body)
	loader.find_templates.cache_clear()
	loader.get_configs_by_type.cache_clear()


def assert_clean_log(log: str):
	for marker in LOG_FORBIDDEN:
		assert marker not in log, f'{marker!r} found in the run output:\n{log[-4000:]}'


@pytest.fixture
def run_ai(model, lab, capfd):
	"""Run the ai task in-process against the scripted model.

	``run_ai(tag, turns, targets=..., **opts)`` scripts ``turns`` for ``tag``, runs the task to
	completion and returns an :class:`AiRun`. The run's output is checked for tracebacks.
	"""
	from secator.tasks.ai import ai

	def _run(tag, turns, targets=None, prompt='', check_log=True, script_only=False, context=None, hooks=None,
	         **opts):
		model.script(turns, tag=tag)
		if script_only:
			return None
		run_opts = dict(
			# prompt=None: no prompt at all (a respawned run resuming its session)
			prompt='' if prompt is None else f'[scenario:{tag}] {prompt or "run the scenario"}',
			mode='scan',
			model=MODEL,
			intent_model=MODEL,
			interactive='auto',
			sensitive=False,
			max_iterations=20,
			print_item=False,
			print_line=False,
			print_progress=False,
			print_start=False,
			print_end=False,
			print_remote_info=False,
			enable_reports=True,
			sync=True,
		)
		run_opts.update(opts)
		if context is not None:
			run_opts['context'] = dict(context)
		if hooks is not None:
			run_opts['hooks'] = hooks
		task = ai(targets if targets is not None else ['127.0.0.1'], **run_opts)
		start = time.monotonic()
		items = task.run()
		elapsed = time.monotonic() - start
		out, err = capfd.readouterr()
		log = out + err
		# Keep the output visible on failure.
		print(log[-20000:])
		# this run's requests only (a resumed session reuses its tag across runs)
		run = AiRun(task=task, items=items, requests=[r for r in model.for_tag(tag) if r.t >= start],
		            elapsed=elapsed, log=log, side_requests=[r for r in model.requests if r.side and r.t >= start])
		if check_log:
			assert_clean_log(log)
		assert tag not in model.overruns, f'scenario {tag!r} ran out of scripted turns'
		return run

	return _run


# ---------------------------------------------------------------------------
# Store drivers (json is the default; mongodb via mongomock; sqlite in a temp file)
# ---------------------------------------------------------------------------

WORKSPACE = 'ai-e2e'


@pytest.fixture
def mongo():
	"""Point the mongodb driver + query backend at an in-memory mongomock client."""
	mongomock = pytest.importorskip('mongomock')
	pytest.importorskip('pymongo')
	from secator.hooks import mongodb as mongo_hooks
	previous = mongo_hooks._mongodb_client
	mongo_hooks._mongodb_client = mongomock.MongoClient()
	yield mongo_hooks._mongodb_client
	mongo_hooks._mongodb_client = previous


@pytest.fixture
def sqlite(tmp_path, monkeypatch):
	from secator.config import CONFIG
	monkeypatch.setattr(CONFIG.addons.sqlite, 'path', str(tmp_path / 'secator.db'))
	return tmp_path / 'secator.db'


@pytest.fixture(params=['json', 'mongodb', 'sqlite'])
def driver(request):
	"""Each store driver in turn; returns the run context selecting it."""
	if request.param == 'mongodb':
		request.getfixturevalue('mongo')
	elif request.param == 'sqlite':
		request.getfixturevalue('sqlite')
	return request.param


def driver_context(driver, **extra):
	return {'drivers': [driver], 'workspace_id': WORKSPACE, 'workspace_name': WORKSPACE, **extra}


def store_for(context):
	"""A query engine over the store the run's drivers write to."""
	from secator.query import QueryEngine
	return QueryEngine(context.get('workspace_id', ''), context=dict(context))


class Answerer:
	"""Answer the remote prompts a run raises, like a client writing the answer to the store.

	``answer(doc) -> str | None`` picks the answer of each pending prompt doc (None: leave it
	pending). Runs in a thread polling the store.
	"""

	def __init__(self, context, answer, types=('stopped', 'permission')):
		self.store = store_for(context)
		self.session_id = context['session_id']
		self.answer = answer
		self.types = types
		self.answered = []
		self._stop = threading.Event()
		self._thread = threading.Thread(target=self._loop, daemon=True)

	def __enter__(self):
		self._thread.start()
		return self

	def __exit__(self, *exc):
		self._stop.set()
		self._thread.join(5)

	def pending(self):
		return [d for d in self.store.search({'_type': 'ai', '_context.session_id': self.session_id,
		                                      'status': 'pending'}) if d.get('ai_type') in self.types]

	def _loop(self):
		while not self._stop.is_set():
			try:
				for doc in self.pending():
					if doc.get('_uuid') in {d.get('_uuid') for d in self.answered}:
						continue
					value = self.answer(doc)
					if value is None:
						continue
					self.store.update({'_type': 'ai', '_uuid': doc['_uuid'], 'status': 'pending'},
					                  {'$set': {'status': 'answered', 'answer': value}})
					self.answered.append(doc)
			except Exception as e:  # noqa: BLE001 - keep polling; the test asserts on outcomes
				print(f'[answerer] {type(e).__name__}: {e}')
			self._stop.wait(0.2)


@pytest.fixture
def remote(monkeypatch):
	"""Fast remote prompts: poll every 0.2s, give up after ``remote.timeout`` seconds."""
	from functools import partial
	from secator.config import CONFIG
	from secator.ai import interactivity
	import importlib
	ai_module = importlib.import_module('secator.tasks.ai')

	class Remote:
		timeout = 4

		def set_timeout(self, seconds):
			monkeypatch.setattr(CONFIG.addons.ai, 'user_response_timeout', seconds)

	r = Remote()
	r.set_timeout(r.timeout)
	monkeypatch.setattr(ai_module, 'create_backend', partial(interactivity.create_backend, poll_interval=0.2))
	return r
