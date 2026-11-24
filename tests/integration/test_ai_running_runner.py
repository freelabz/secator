# tests/integration/test_ai_running_runner.py
"""The ai task reads a RUNNING runner's live status and partial findings, and asks before
stopping a runner it did not start.

A real ``ai`` task (json driver, in-process) is driven by a scripted model: no LLM is called,
``call_llm`` returns the next tool call of a script that reads the previous tool results. The
running runner is a real httpx run started outside the ai task, in the same workspace, against
a local HTTP server whose ``/slow*`` pages answer after a delay, so the ``/fast`` URL is stored
while it still runs.
"""
import json
import re
import shutil
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from secator.definitions import ADDONS_ENABLED

SLOW_DELAY = 6


def _httpx_installed():
	try:
		from secator.tasks.httpx import httpx
		return bool(shutil.which(httpx.cmd.split()[0]))
	except Exception:  # noqa: BLE001
		return False


class _Handler(BaseHTTPRequestHandler):
	def do_GET(self):  # noqa: N802
		if self.path.startswith("/slow"):
			time.sleep(SLOW_DELAY)
		if self.path.startswith("/hang"):
			time.sleep(60)
		body = f"<html><title>{self.path}</title></html>".encode()
		self.send_response(200)
		self.send_header("Content-Type", "text/html")
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, *args):
		pass


_DATA_RE = re.compile(r"<workspace_data>\n(.*)\n</workspace_data>", re.DOTALL)


def _parse(content):
	m = _DATA_RE.search(content or "")
	try:
		return json.loads(m.group(1) if m else content)
	except (TypeError, ValueError):
		return {"raw": content}


class ScriptedModel:
	"""Stands in for ``call_llm``: plays a script, a generator that yields
	``(tool_name, arguments)`` and receives the parsed results of that call back."""

	def __init__(self, script):
		self.gen = script()
		self.started = False
		self.calls = 0
		self.error = None

	def __call__(self, messages, model, temp, api_base, api_key, tools=None):
		# The tool results of the previous call: the tool messages after the last assistant turn
		# (a per-turn status block may follow them).
		tail = []
		for m in reversed(messages):
			if m.get("role") == "assistant":
				break
			if m.get("role") == "tool":
				tail.insert(0, _parse(m.get("content")))
		try:
			step = self.gen.send(tail) if self.started else next(self.gen)
			self.started = True
		except StopIteration:
			step = None
		except Exception as e:  # noqa: BLE001 - surfaced by the test, not swallowed by the loop
			self.error = e
			step = None
		usage = {"tokens": 10, "prompt_tokens": 5, "completion_tokens": 5, "cost": 0.0}
		if step is None:
			return {"content": "Done.", "tool_calls": [], "usage": usage, "finish_reason": "stop"}
		self.calls += 1
		name, args = step
		tc = SimpleNamespace(id=f"call_{self.calls}", type="function",
		                     function=SimpleNamespace(name=name, arguments=json.dumps(args)))
		return {"content": "", "tool_calls": [tc], "usage": usage, "finish_reason": "tool_calls"}


def _path(url):
	# The model sees target IPs as placeholders (sensitive-data encryption): compare paths.
	return "/" + (url or "").split("/", 3)[-1]


def _results(tail):
	return (tail[0] or {}).get("results", []) if tail else []


@unittest.skipUnless(ADDONS_ENABLED['ai'] and _httpx_installed(), "ai addon and httpx required")
class TestAiPartialResults(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
		cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
		threading.Thread(target=cls.server.serve_forever, daemon=True).start()

	@classmethod
	def tearDownClass(cls):
		cls.server.shutdown()

	def setUp(self):
		self.reports = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.reports, ignore_errors=True)

	def _run(self, script, targets):
		from secator.tasks.ai import ai as AiTask
		model = ScriptedModel(script)
		patches = [
			patch("secator.tasks.ai.call_llm", model),
			patch("secator.tasks.ai.init_llm", lambda **k: None),
			patch.object(AiTask, "_verify_model", lambda self: iter(())),
			patch("secator.config.CONFIG.dirs.reports", Path(self.reports)),
		]
		with ExitStack() as stack:
			for p in patches:
				stack.enter_context(p)
			task = AiTask(targets, prompt="probe the targets", mode="scan", model="gpt-4o", api_key="test",
			              interactive=False, dangerous=True, driver="json", max_iterations=40,
			              sync=True, print_item=False, print_line=False, quiet=True)
			items = list(task)
		if model.error is not None:
			raise model.error
		return task, items

	def _start_external_httpx(self, urls):
		"""A runner started outside the ai task (e.g. a scan someone runs in the workspace)."""
		from secator.tasks.httpx import httpx
		with patch("secator.config.CONFIG.dirs.reports", Path(self.reports)):
			runner = httpx(urls, driver="json", threads=5, sync=True, print_item=False, print_line=False,
			               quiet=True, timeout=60)
		thread = threading.Thread(target=lambda: list(runner), daemon=True)
		with patch("secator.config.CONFIG.dirs.reports", Path(self.reports)):
			thread.start()
		return runner, thread

	def test_reads_partial_results_of_a_running_runner_then_full_set(self):
		base = self.base
		urls = [f"{base}/fast", f"{base}/slow1", f"{base}/slow2"]
		ext, thread = self._start_external_httpx(urls)
		seen = {}

		def script():
			# Find the running runner in the workspace run history.
			row = None
			for _ in range(50):
				tail = yield ("list_runners", {"runner_type": "task", "status": "RUNNING"})
				row = next((r for r in _results(tail) if r.get("name") == "httpx"), None)
				if row:
					break
				time.sleep(0.1)
			seen["row"] = row
			view, partial = {}, []
			for _ in range(60):
				tail = yield ("get_runner", {"runner_id": row["run_id"], "runner_type": "task"})
				view = next((r for r in _results(tail) if r.get("_type") == "runner_status"), {})
				tail = yield ("query_workspace", {"query": {**view["query"], "_type": "url"}})
				partial = [_path(r.get("url")) for r in _results(tail) if r.get("_type") == "url"]
				if partial:
					break
				time.sleep(0.2)
			seen["mid_view"], seen["partial"] = view, partial
			seen["still_running_after_partial"] = thread.is_alive()
			for _ in range(100):  # re-query later, as the prompt says
				tail = yield ("get_runner", {"runner_id": row["run_id"], "runner_type": "task"})
				view = next((r for r in _results(tail) if r.get("_type") == "runner_status"), {})
				if view.get("done"):
					break
				time.sleep(0.3)
			seen["end_view"] = view
			tail = yield ("query_workspace", {"query": {**view["query"], "_type": "url"}})
			seen["full"] = sorted(_path(r.get("url")) for r in _results(tail) if r.get("_type") == "url")
			# Not started by this ai task: stopping it needs the user, and this run has none.
			tail = yield ("stop_runner", {"runner_id": row["run_id"], "runner_type": "task", "reason": "test"})
			seen["stop"] = tail

		self._run(script, [base])
		thread.join(30)
		self.assertIsNotNone(seen["row"])
		self.assertEqual(seen["partial"], ["/fast"])  # some findings before the runner completed
		self.assertTrue(seen["still_running_after_partial"])
		self.assertEqual(seen["mid_view"]["status"], "RUNNING")
		self.assertLess(seen["mid_view"].get("findings", {}).get("url", 0), 3)  # partial counts
		self.assertEqual(seen["end_view"]["status"], "SUCCESS")
		self.assertEqual(seen["full"], ["/fast", "/slow1", "/slow2"])  # the full set once it is done
		self.assertEqual(seen["end_view"]["findings"].get("url"), 3)

	def test_stopping_a_runner_it_did_not_start_needs_the_user(self):
		base = self.base
		ext, thread = self._start_external_httpx([f"{base}/hang"])
		seen = {}

		def script():
			row = None
			for _ in range(50):
				tail = yield ("list_runners", {"runner_type": "task", "status": "RUNNING"})
				row = next((r for r in _results(tail) if r.get("name") == "httpx"), None)
				if row:
					break
				time.sleep(0.1)
			tail = yield ("stop_runner", {"runner_id": row["run_id"], "runner_type": "task", "reason": "hangs"})
			seen["stop"] = json.dumps(tail)

		self._run(script, [base])
		# A non-interactive run has nobody to approve: the runner keeps running.
		self.assertIn("did not approve stopping task httpx", seen["stop"])
		self.assertTrue(thread.is_alive())
		ext.stop_process(exit_ok=True)


if __name__ == "__main__":
	unittest.main()
