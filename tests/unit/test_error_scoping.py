"""Error-scoping regression tests.

In a scan, results forward from one workflow to the next, so a workflow's
``results`` can contain ``Error`` outputs produced by an *earlier sibling*
workflow. Status is ``FAILURE if self_errors else SUCCESS``, and ``self_errors``
for a workflow used to count *every* error in ``results`` — so a later workflow
wrongly reported FAILURE even when all of its own tasks succeeded.

The fix scopes a workflow's errors to its own subtree (``ancestor_id`` ==
the workflow's config name, or a workflow-level error from its own ``_source``),
while a scan keeps aggregating every descendant error.
"""
import unittest

from secator.runners import Scan, Workflow
from secator.output_types import Error
from secator.loader import get_configs_by_type


class TestErrorScoping(unittest.TestCase):
	def _workflow(self):
		workflows = get_configs_by_type('workflow')
		if not workflows:
			self.skipTest('No workflows configured')
		wf = Workflow(workflows[0], inputs=['example.com'], run_opts={'dry_run': True}, context={})
		wf.started = True
		wf.done = True
		return wf

	def test_workflow_ignores_sibling_forwarded_error(self):
		wf = self._workflow()
		# An error produced by a different (earlier) workflow, forwarded into this one.
		foreign = Error(message='boom', _source='other.task', _context={'ancestor_id': 'other_workflow'})
		wf.add_result(foreign, print=False, output=False, hooks=False, queue=False)
		self.assertEqual(wf.self_errors, [], 'workflow must not inherit a sibling workflow error')
		self.assertEqual(wf.status, 'SUCCESS')

	def test_workflow_counts_its_own_subtree_error(self):
		wf = self._workflow()
		own = Error(message='mine', _source=f'{wf.config.name}.task', _context={'ancestor_id': wf.config.name})
		wf.add_result(own, print=False, output=False, hooks=False, queue=False)
		self.assertIn(own, wf.self_errors)
		self.assertEqual(wf.status, 'FAILURE')

	def test_workflow_counts_its_own_direct_error(self):
		# A workflow-level error (not from a task) carries the workflow's own _source.
		wf = self._workflow()
		direct = Error(message='wf-level', _source=wf.unique_name)
		wf.add_result(direct, print=False, output=False, hooks=False, queue=False)
		self.assertIn(direct, wf.self_errors)
		self.assertEqual(wf.status, 'FAILURE')

	def test_scan_aggregates_all_descendant_errors(self):
		scans = get_configs_by_type('scan')
		if not scans:
			self.skipTest('No scans configured')
		scan = Scan(scans[0], inputs=['example.com'], run_opts={'dry_run': True}, context={})
		scan.started = True
		scan.done = True
		# An error from any child workflow's subtree must make the scan FAILURE.
		e = Error(message='child failed', _source='wf.task', _context={'ancestor_id': 'some_workflow'})
		scan.add_result(e, print=False, output=False, hooks=False, queue=False)
		self.assertIn(e, scan.self_errors)
		self.assertEqual(scan.status, 'FAILURE')


if __name__ == '__main__':
	unittest.main()
