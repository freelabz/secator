"""Regression: the runner-start marker must not force a large-pool cold start.

`mark_runner_started` used to always dispatch to the `results` queue (served by
the memory-heavy *large* worker pool) so a workflow deep in a scan could load
its forwarded results in memory. But a scan's start — and a parentless /
first-in-scan workflow's start — carries an empty result set (`si([], ...)`), so
it doesn't need that headroom. Forcing it onto the large pool triggered a
KEDA scale-from-zero node provision just to *mark the runner started*, which
dominated scan/workflow start latency.

These tests pin the routing: an empty-results start goes to `small`; a start
that chains forwarded results (a workflow inside a scan) stays on `results`.
"""
import unittest

from secator.runners import Scan, Workflow
from secator.loader import get_configs_by_type


def _first_task_queue(canvas):
    """Queue of the first step (mark_runner_started) of a built celery chain."""
    tasks = getattr(canvas, 'tasks', None)
    assert tasks, f'expected a chain canvas with .tasks, got {canvas!r}'
    return tasks[0].options.get('queue')


class TestMarkStartedQueue(unittest.TestCase):
    def _workflow(self):
        workflows = get_configs_by_type('workflow')
        if not workflows:
            self.skipTest('No workflows configured')
        return Workflow(workflows[0], inputs=['example.com'], run_opts={'dry_run': True}, context={})

    def test_parentless_workflow_start_routes_to_small(self):
        wf = self._workflow()
        canvas = wf.build_celery_workflow(chain_previous_results=False)
        self.assertEqual(_first_task_queue(canvas), 'small')

    def test_workflow_chaining_results_stays_on_results(self):
        wf = self._workflow()
        canvas = wf.build_celery_workflow(chain_previous_results=True)
        self.assertEqual(_first_task_queue(canvas), 'results')

    def test_workflow_light_start_routes_to_small(self):
        # A scan's first workflow keeps `.s(self)` (chain_previous_results=True) —
        # so it still receives the scan-start's forwarded results — but its start is
        # light (that set is empty), so `light_start` routes just the queue to small.
        wf = self._workflow()
        canvas = wf.build_celery_workflow(chain_previous_results=True, light_start=True)
        self.assertEqual(_first_task_queue(canvas), 'small')

    def test_scan_start_routes_to_small(self):
        scans = get_configs_by_type('scan')
        if not scans:
            self.skipTest('No scans configured')
        scan = Scan(scans[0], inputs=['example.com'], run_opts={'dry_run': True}, context={})
        canvas = scan.build_celery_workflow()
        self.assertEqual(_first_task_queue(canvas), 'small')
