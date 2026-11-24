# tests/integration/test_ai_background_partial_results.py
"""The ai task reads a RUNNING background job's partial findings, then the full set.

A real ``ai`` task (json driver, in-process) is driven by a scripted model: no LLM is called,
``call_llm`` returns the next tool call of a script that reads the previous tool results. The
background job is a real httpx run against a local HTTP server whose ``/slow*`` pages answer
after a delay, so the ``/fast`` URL is stored while the job still runs.
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

	def test_reads_partial_results_while_running_then_full_set(self):
		base = self.base
		urls = [f"{base}/fast", f"{base}/slow1", f"{base}/slow2"]
		seen = {}

		def script():
			tail = yield ("run_task", {"name": "httpx", "targets": urls, "background": True,
			                           "description": "Probe the URLs", "opts": {"threads": 5}})
			# The job's runners are listed as soon as the child runner is built.
			runner = None
			for _ in range(50):
				tail = yield ("check_background_jobs", {"job_ids": ["bg-1"]})
				status = next((r for r in _results(tail) if r.get("_type") == "background_job"), {})
				if status.get("runners"):
					runner = status["runners"][0]
					break
				time.sleep(0.1)
			seen["runner"] = runner
			query = runner["query"]
			# Partial findings while the job still runs.
			partial = []
			for _ in range(60):
				tail = yield ("query_workspace", {"query": {**query, "_type": "url"}})
				partial = [_path(r.get("url")) for r in _results(tail) if r.get("_type") == "url"]
				if partial:
					break
				time.sleep(0.2)
			seen["partial"] = partial
			tail = yield ("check_background_jobs", {"job_ids": ["bg-1"]})
			seen["job_status_after_partial"] = next(
				(r for r in _results(tail) if r.get("_type") == "background_job"), {}).get("status")
			tail = yield ("check_background_jobs", {"job_ids": ["bg-1"], "wait": 60})
			seen["job_status_end"] = next(
				(r for r in _results(tail) if r.get("_type") == "background_job"), {}).get("status")
			tail = yield ("query_workspace", {"query": {**query, "_type": "url"}})
			seen["full"] = sorted(_path(r.get("url")) for r in _results(tail) if r.get("_type") == "url")

		self._run(script, [base])
		self.assertEqual(seen["runner"]["type"], "task")
		self.assertEqual(seen["partial"], ["/fast"])  # some findings before the job completed
		self.assertEqual(seen["job_status_after_partial"], "running")
		self.assertEqual(seen["full"], ["/fast", "/slow1", "/slow2"])  # the full set once it is done
		self.assertEqual(seen["job_status_end"], "done")


if __name__ == "__main__":
	unittest.main()
