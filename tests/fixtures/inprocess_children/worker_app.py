"""Worker module for tests/unit/test_inprocess_children_pools.py.

Loaded with ``celery -A secator.celery.app worker -I worker_app -P <pool>``. Its task runs a
child task in-process through the same code path the ``ai`` task uses for a light child
(``_run_runner`` with a sync context), and reports what came back.
"""
from celery._state import task_join_will_block

from secator.celery import app


@app.task(name='tests.run_inprocess_child')
def run_inprocess_child(targets):
	from secator.ai.actions import ActionContext
	from secator.ai.tools._runner import _run_runner
	ctx = ActionContext(targets=targets, model='', sync=True, silent=True, context={})
	action = {'name': 'inproc_echo', 'targets': targets, 'opts': {}}
	items = list(_run_runner(action, ctx, 'task'))
	return {
		'join_will_block': task_join_will_block(),
		'tags': sorted(i.value for i in items if getattr(i, '_type', None) == 'tag'),
		'errors': [i.message for i in items if getattr(i, '_type', None) == 'error'],
	}
