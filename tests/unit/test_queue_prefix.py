"""Queue-prefix routing: a resolved queue name is prefixed with ``<prefix>-`` so a
worker fleet can subscribe to a dedicated set of queues and a run can target it.

Covers: derivation precedence (run opts > CONFIG > none), prefixed task/lifecycle
routing, the worker-subscription queue set, and the no-prefix default (byte-identical
to today).
"""
import unittest

from secator.config import CONFIG
from secator.loader import get_configs_by_type
from secator.runners import Scan, Workflow
from secator.runners._helpers import prefix_queue, resolve_queue_prefix


def _first_task_queue(canvas):
    tasks = getattr(canvas, 'tasks', None)
    assert tasks, f'expected a chain canvas with .tasks, got {canvas!r}'
    return tasks[0].options.get('queue')


class TestQueuePrefixDerivation(unittest.TestCase):
    def setUp(self):
        self._orig = CONFIG.celery.queue_prefix

    def tearDown(self):
        CONFIG.celery.queue_prefix = self._orig

    def test_none_by_default(self):
        CONFIG.celery.queue_prefix = ''
        self.assertIsNone(resolve_queue_prefix({}))
        self.assertIsNone(resolve_queue_prefix(None))

    def test_run_opts_wins_over_config(self):
        CONFIG.celery.queue_prefix = 'cfg'
        self.assertEqual(resolve_queue_prefix({'queue_prefix': 'run'}), 'run')

    def test_config_fallback(self):
        CONFIG.celery.queue_prefix = 'cfg'
        self.assertEqual(resolve_queue_prefix({}), 'cfg')

    def test_prefix_queue_noop_when_unset(self):
        CONFIG.celery.queue_prefix = ''
        self.assertEqual(prefix_queue('small', {}), 'small')

    def test_prefix_queue_applies(self):
        self.assertEqual(prefix_queue('small', {'queue_prefix': 'fleet1'}), 'fleet1-small')


class TestQueuePrefixRouting(unittest.TestCase):
    def _workflow(self, run_opts):
        workflows = get_configs_by_type('workflow')
        if not workflows:
            self.skipTest('No workflows configured')
        return Workflow(workflows[0], inputs=['example.com'], run_opts=run_opts, context={})

    def test_start_marker_unprefixed_by_default(self):
        wf = self._workflow({'dry_run': True})
        canvas = wf.build_celery_workflow(chain_previous_results=False)
        self.assertEqual(_first_task_queue(canvas), 'small')

    def test_start_marker_prefixed_from_run_opts(self):
        wf = self._workflow({'dry_run': True, 'queue_prefix': 'fleet1'})
        canvas = wf.build_celery_workflow(chain_previous_results=False)
        self.assertEqual(_first_task_queue(canvas), 'fleet1-small')

    def test_scan_start_prefixed_from_run_opts(self):
        scans = get_configs_by_type('scan')
        if not scans:
            self.skipTest('No scans configured')
        scan = Scan(scans[0], inputs=['example.com'], run_opts={'dry_run': True, 'queue_prefix': 'c1'}, context={})
        canvas = scan.build_celery_workflow()
        self.assertEqual(_first_task_queue(canvas), 'c1-small')


class TestWorkerSubscription(unittest.TestCase):
    """Mirror the worker's default queue-set derivation (secator/cli.py worker)."""

    BASE = ['small', 'medium', 'large', 'extra_large', 'poll', 'celery', 'results', 'mongodb']

    def _subscription(self, prefix):
        return [f'{prefix}-{q}' if prefix else q for q in self.BASE]

    def test_no_prefix_identical(self):
        self.assertEqual(self._subscription(''), self.BASE)

    def test_prefixed_every_queue(self):
        subs = self._subscription('fleet1')
        self.assertEqual(subs[0], 'fleet1-small')
        self.assertTrue(all(q.startswith('fleet1-') for q in subs))
        self.assertIn('fleet1-mongodb', subs)


if __name__ == '__main__':
    unittest.main()
