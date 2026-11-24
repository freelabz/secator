"""Worker module for tests/unit/test_inprocess_children_pools.py.

Loaded with ``celery -A secator.celery.app worker -I worker_app -P <pool>``. Its task runs a
child task in-process through the same code path the ``ai`` task uses for a light child
(``_run_runner`` with a sync context), and reports what came back.
"""
from unittest import mock

from celery._state import task_join_will_block

from secator.celery import app


@app.task(name='tests.run_inprocess_child')
def run_inprocess_child(targets):
	from secator.ai.actions import ActionContext
	from secator.ai.tools import _runner
	from secator.ai.utils import _is_heavy_runner
	# In a worker, a child that would chunk is dispatched to its own queue, which this test
	# worker does not consume: the dispatched child would never run and the task would wait
	# for it forever. Record the dispatch decision, then force the child in-process so the
	# eager chunked path (chord / Task.replace) is still exercised under every pool.
	would_dispatch = _is_heavy_runner('task', 'inproc_echo', {}, targets)
	ctx = ActionContext(targets=targets, model='', sync=True, silent=True, context={})
	action = {'name': 'inproc_echo', 'targets': targets, 'opts': {}}
	with mock.patch.object(_runner, '_is_heavy_runner', return_value=False):
		items = list(_runner._run_runner(action, ctx, 'task'))
	return {
		'would_dispatch': would_dispatch,
		'join_will_block': task_join_will_block(),
		'tags': sorted(i.value for i in items if getattr(i, '_type', None) == 'tag'),
		'errors': [i.message for i in items if getattr(i, '_type', None) == 'error'],
	}
