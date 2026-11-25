"""Worker module of tests/unit/test_revoked_runners_worker.py (``celery worker -I worker_app``).

Its task runs child commands in-process, in parallel threads, through the batch code path the
``ai`` task runs a turn's tool calls with (as its shell tool runs a command).
"""
import sys
from unittest import mock

from celery.signals import worker_ready

from secator.ai import actions
from secator.celery import app
from secator.runners import Task


@worker_ready.connect
def announce_ready(**kwargs):
	print('REVOKE-TEST-WORKER-READY', file=sys.stderr, flush=True)


@app.task(name='tests.run_batch_children')
def run_batch_children(seconds):
	task_cls = Task.get_task_class('revoke_sleep')

	def dispatch(action, ctx):
		runner = task_cls([action['seconds']], context={'drivers': ['json']}, enable_reports=False)
		ctx.record_runner(runner, action['seconds'])
		yield from runner

	ctx = actions.ActionContext(targets=[], model='', silent=True)
	with mock.patch.object(actions, 'safe_dispatch_action', dispatch):
		for _ in actions._run_batch([{'action': 'task', 'seconds': s} for s in seconds], ctx):
			pass
