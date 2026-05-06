import unittest
from unittest.mock import patch

from secator.decorators import task
from secator.definitions import HOST
from secator.output_types import Port
from secator.runners import PythonRunner
from secator.template import TemplateLoader


@task()
class fake_a(PythonRunner):
    input_types = [HOST]
    output_types = [Port]

    def yielder(self):
        yield Port(ip='1.2.3.4', host='1.2.3.4', port=80, protocol='tcp')


@task()
class fake_b(PythonRunner):
    input_types = [HOST]
    output_types = [Port]

    def yielder(self):
        yield Port(ip='1.2.3.4', host='1.2.3.4', port=443, protocol='tcp')


MOCK_TASKS = [fake_a, fake_b]


def patched_discover():
    return MOCK_TASKS


def make_workflow_config():
    return TemplateLoader(input={
        'name': 'test_wf',
        'type': 'workflow',
        'input_types': ['host'],
        'tasks': {
            'fake_a': {'description': 'First task'},
            'fake_b': {'description': 'Second task'},
        }
    })


class TestWorkflowSkip(unittest.TestCase):

    def _build(self, skip):
        from secator.runners import Workflow
        config = make_workflow_config()
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover):
            wf = Workflow(config, inputs=['example.com'], run_opts={'skip': skip})
            wf.build_celery_workflow()
        return wf

    def test_skipped_task_absent_from_celery_graph(self):
        """A task in the skip list must not appear in celery_ids_map."""
        wf = self._build(skip=['fake_a'])
        names_in_graph = [info['name'] for info in wf.celery_ids_map.values()]
        self.assertNotIn('fake_a', names_in_graph)
        self.assertIn('fake_b', names_in_graph)

    def test_skipped_task_emits_info(self):
        """A skipped task must emit an Info result with the task name."""
        wf = self._build(skip=['fake_a'])
        info_messages = [r.message for r in wf.results if r._type == 'info']
        self.assertTrue(any('fake_a' in m for m in info_messages),
                        f"No Info message about 'fake_a' in: {info_messages}")

    def test_empty_skip_runs_all_tasks(self):
        """With no skip list, all tasks appear in the graph."""
        wf = self._build(skip=[])
        names_in_graph = [info['name'] for info in wf.celery_ids_map.values()]
        self.assertIn('fake_a', names_in_graph)
        self.assertIn('fake_b', names_in_graph)

    def test_unknown_skip_name_is_ignored(self):
        """A skip name that matches no task must not affect execution."""
        wf = self._build(skip=['nonexistent_task'])
        names_in_graph = [info['name'] for info in wf.celery_ids_map.values()]
        self.assertIn('fake_a', names_in_graph)
        self.assertIn('fake_b', names_in_graph)

    def _build_grouped(self, skip):
        from secator.runners import Workflow
        config = TemplateLoader(input={
            'name': 'test_wf_grouped',
            'type': 'workflow',
            'input_types': ['host'],
            'tasks': {
                '_group': {
                    'fake_a': {'description': 'First group task'},
                    'fake_b': {'description': 'Second group task'},
                }
            }
        })
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover):
            wf = Workflow(config, inputs=['example.com'], run_opts={'skip': skip})
            wf.build_celery_workflow()
        return wf

    def test_skip_inside_group(self):
        """A task inside a _group: block must be skippable by name."""
        wf = self._build_grouped(skip=['fake_a'])
        names_in_graph = [info['name'] for info in wf.celery_ids_map.values()]
        self.assertNotIn('fake_a', names_in_graph)
        self.assertIn('fake_b', names_in_graph)


class TestScanSkipRouting(unittest.TestCase):
    """Verify that scan-level skip entries are routed to the correct child workflow."""

    def _compute_wf_skip(self, skip, wf_name):
        """Replicate the routing logic from scan.build_celery_workflow()."""
        scoped = [s.split('.', 1)[1] for s in skip if s.startswith(f'{wf_name}.')]
        bare = [s for s in skip if '.' not in s]
        return scoped + bare

    def test_scoped_entry_routes_to_correct_workflow(self):
        """'workflow1.fake_a' must produce ['fake_a'] for workflow1."""
        result = self._compute_wf_skip(['workflow1.fake_a'], 'workflow1')
        self.assertEqual(result, ['fake_a'])

    def test_scoped_entry_does_not_route_to_other_workflow(self):
        """'workflow1.fake_a' must produce [] for workflow2."""
        result = self._compute_wf_skip(['workflow1.fake_a'], 'workflow2')
        self.assertEqual(result, [])

    def test_bare_entry_routes_to_all_workflows(self):
        """'fake_a' (no dot) must appear in skip list for every workflow."""
        result_wf1 = self._compute_wf_skip(['fake_a'], 'workflow1')
        result_wf2 = self._compute_wf_skip(['fake_a'], 'workflow2')
        self.assertIn('fake_a', result_wf1)
        self.assertIn('fake_a', result_wf2)

    def test_mixed_entries(self):
        """Mixed scoped and bare entries route correctly."""
        skip = ['workflow1.fake_a', 'fake_b']
        result_wf1 = self._compute_wf_skip(skip, 'workflow1')
        result_wf2 = self._compute_wf_skip(skip, 'workflow2')
        self.assertIn('fake_a', result_wf1)
        self.assertIn('fake_b', result_wf1)
        self.assertNotIn('fake_a', result_wf2)
        self.assertIn('fake_b', result_wf2)
