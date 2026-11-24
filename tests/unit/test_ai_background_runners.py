# tests/unit/test_ai_background_runners.py
"""A running background job exposes its runners (id, type, scoping query) from their start."""

import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import ActionContext
	from secator.ai.background import BackgroundJobs, register_runner_hook, add_background_hooks, RUNNING
	from secator.ai.tools.runners import CheckBackgroundJobs
	from secator.output_types import Ai, Error, Warning


def _runner(rtype="task", name="httpx", sync=True, celery_ids=None, **ctx):
	return SimpleNamespace(
		config=SimpleNamespace(type=rtype, name=name), context=dict(ctx), sync=sync, done=False,
		celery_ids_map={i: {} for i in (celery_ids or [])}, stop_process=MagicMock(),
		stop_celery_tasks=MagicMock())


def _blocking_dispatch(runner, release):
	"""A job whose child runner registers (its on_init), emits its card, then runs until released."""
	def dispatch(action, ctx):
		register_runner_hook(runner)
		rid = runner.context.get("task_chunk_id") or runner.context.get(f"{runner.config.type}_id")
		yield Ai(content=runner.config.name, ai_type=runner.config.type,
		         extra_data={"runner_id": rid, "runner_type": runner.config.type},
		         _context={"tool_call_id": action.get("tool_call_id")})
		release.wait(10)
	return dispatch


def _action(**kw):
	return {"action": "task", "name": "httpx", "targets": ["a"], "tool_call_id": "tc1",
	        "tool_call_name": "run_task", "background": True, **kw}


def _results(gen):
	out = list(gen)
	return [o for o in out if isinstance(o, dict)], [o for o in out if isinstance(o, (Error, Warning))]


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestJobRunnersExposed(unittest.TestCase):

	def test_status_lists_runner_id_type_and_query_while_running(self):
		release = threading.Event()
		mgr = BackgroundJobs(max_jobs=3, max_wait=10)
		ctx = ActionContext(targets=["a"], model="m", results=[], background=mgr)
		runner = _runner(task_chunk_id="chunk-1", task_id="tid-1")
		job = mgr.submit(_action(), ctx, _blocking_dispatch(runner, release))
		try:
			deadline = time.time() + 5
			while not job.items and time.time() < deadline:
				time.sleep(0.01)
			self.assertEqual(job.status, RUNNING)
			status = job.to_dict()
			self.assertEqual(status["runners"], [
				{"id": "chunk-1", "type": "task", "name": "httpx", "query": {"_context.task_id": "tid-1"}}])
			self.assertEqual(status["runner_ids"], ["chunk-1"])  # kept for existing callers
			# The check_background_jobs tool result carries it too.
			dicts, _ = _results(CheckBackgroundJobs().run({"tool_call_id": "tc2"}, ctx))
			self.assertEqual(dicts[0]["runners"][0]["id"], "chunk-1")
		finally:
			release.set()
			job.thread.join(5)

	def test_real_runner_registers_at_construction(self):
		"""A child runner is attached to its job by its on_init hook, i.e. when it is BUILT
		(before it runs), so its ids are known for the whole run."""
		from secator.runners import Task
		from secator.template import TemplateLoader
		release = threading.Event()
		mgr = BackgroundJobs(max_jobs=3, max_wait=10)
		ctx = ActionContext(targets=["a"], model="m", results=[], background=mgr)
		built = {}

		def dispatch(action, ctx):
			tpl = TemplateLoader(input={"type": "task", "name": "httpx"})
			built["runner"] = Task(tpl, ["http://127.0.0.1:1"], run_opts={"sync": True},
			                       hooks=add_background_hooks({}), context={"task_chunk_id": "chunk-9"})
			yield Ai(content="httpx", ai_type="task", extra_data={"runner_id": "chunk-9"})
			release.wait(10)
		job = mgr.submit(_action(), ctx, dispatch)
		try:
			deadline = time.time() + 10
			while not job.items and time.time() < deadline:
				time.sleep(0.01)
			ref, = job.runner_refs()
			self.assertEqual((ref["id"], ref["type"], ref["name"]), ("chunk-9", "task", "httpx"))
			self.assertEqual(ref["query"], {"_context.task_id": built["runner"].context["task_id"]})
		finally:
			release.set()
			job.thread.join(5)

	def test_card_only_runner_is_listed(self):
		mgr = BackgroundJobs(max_jobs=3, max_wait=10)
		ctx = ActionContext(targets=["a"], model="m", results=[], background=mgr)

		def dispatch(action, ctx):
			yield Ai(content="recon", ai_type="workflow", extra_data={"runner_id": "wf-1", "runner_type": "workflow"})
		job = mgr.submit(_action(), ctx, dispatch)
		job.thread.join(5)
		self.assertEqual(job.runner_refs(), [{"id": "wf-1", "type": "workflow", "name": "recon"}])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestPartialResultsPrompt(unittest.TestCase):

	def test_background_rule(self):
		from secator.ai.prompts import get_system_prompt
		scan = get_system_prompt("scan")
		self.assertIn("check_background_jobs lists each job's `runners` (`id`, `type`, `query`)", scan)
		self.assertIn("They are PARTIAL until the job is done", scan)
		self.assertIn('"_timestamp": {"$gt"', scan)


if __name__ == '__main__':
	unittest.main()
