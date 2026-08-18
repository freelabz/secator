"""Regression tests for target filtering through a scan -> workflow -> task chain.

freelabz/secator#1328: since the store-backed extractor rework (#1312), a scan that filters
targets into a workflow (`targets_` in the scan template) AND a task inside that workflow that
also filters targets (`targets_` in the workflow template) left the task with NO inputs.

Root cause: the `mark_runner_started` pass that resolves a workflow's own `targets_` to EMIT the
scope-tagged Targets was itself scoped by `parent_scope` in build_extractor_query, so it queried
the very scope it was about to create, found nothing, and emitted nothing — leaving every task in
the workflow that filters (or relies on the scope fallback) with no targets.
"""
import unittest
from unittest.mock import patch

from secator.decorators import task
from secator.output_types import Target
from secator.runners import Scan
from secator.runners.command import Command
from secator.template import TemplateLoader


# --- Pure-python mock task: record the inputs it RESOLVED to (after target filtering) ---
RESOLVED = {}


@task()
class mockscantask(Command):
	cmd = 'true'
	input_types = []  # accept any input
	output_types = [Target]

	def _run_extractors(self):
		super()._run_extractors()
		# Target filtering is applied here; capture what the task ended up with.
		RESOLVED[self.unique_name] = sorted(self.inputs)

	def yielder(self):
		for name in self.inputs:
			yield Target(name=name)


def _wf(name, task_targets_):
	"""A one-task workflow; the task filters targets by `type: target, field: name`."""
	tasks = {'mockscantask/mytask': {}}
	if task_targets_ is not None:
		tasks['mockscantask/mytask'] = {'targets_': task_targets_}
	return TemplateLoader(input={'type': 'workflow', 'name': name, 'tasks': tasks})


class TestTargetFilterScope(unittest.TestCase):

	INPUTS = ['host-a.test', 'host-b.test', 'host-c.test']

	def setUp(self):
		RESOLVED.clear()
		# Register the mock task and serve inline workflow templates by name.
		import secator.runners.task as task_mod
		import secator.loader as loader_mod
		self._orig_discover = task_mod.discover_tasks
		task_mod.discover_tasks = lambda: list(self._orig_discover()) + [mockscantask]
		self._templates = []
		self._patch_ft = patch.object(loader_mod, 'find_templates', side_effect=lambda: self._templates)
		self._patch_ft.start()

	def tearDown(self):
		import secator.runners.task as task_mod
		task_mod.discover_tasks = self._orig_discover
		self._patch_ft.stop()

	def _run_scan(self, wf2_scan_targets_, mytask_targets_):
		"""Scan: wf1 (no filter) then wf2 (scan-level targets_ = `wf2_scan_targets_`).
		wf2 contains one task that filters by `mytask_targets_`. Returns mytask's resolved inputs."""
		self._templates = [
			_wf('wf1', None),
			_wf('wf2', mytask_targets_),
		]
		scan_cfg = TemplateLoader(input={
			'type': 'scan', 'name': 'myscan',
			'workflows': {'wf1': {}, 'wf2': {'targets_': wf2_scan_targets_}},
		})
		scan = Scan(scan_cfg, self.INPUTS, run_opts={'sync': True}, context={})
		list(scan)
		return next((inp for name, inp in RESOLVED.items() if 'mytask' in name), None)

	def test_identity_filter_passes_all_targets(self):
		"""#1328: task with `targets_` under a scan-filtered workflow must receive the workflow's
		targets (here: all of them), not an empty list."""
		mytask_inputs = self._run_scan(
			wf2_scan_targets_={'type': 'target', 'field': 'name'},
			mytask_targets_={'type': 'target', 'field': 'name'},
		)
		self.assertEqual(mytask_inputs, sorted(self.INPUTS))

	def test_scan_level_subset_filter_is_honored(self):
		"""When the scan-level filter selects a SUBSET, the nested task must receive exactly that
		subset (not all targets) — proves the fix keeps the scope filter on the consumer side."""
		mytask_inputs = self._run_scan(
			wf2_scan_targets_={'type': 'target', 'field': 'name', 'condition': "name == 'host-a.test'"},
			mytask_targets_={'type': 'target', 'field': 'name'},
		)
		self.assertEqual(mytask_inputs, ['host-a.test'])


if __name__ == '__main__':
	unittest.main()
