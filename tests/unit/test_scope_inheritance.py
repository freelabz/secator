"""Linchpin test for PR3 of the target-scoping rework.

Run-scope (`in_scope`/`out_of_scope`) set on a ROOT runner's run_opts must reach EVERY descendant
runner (scan -> workflow -> task, including the dynamically-spawned fan-out where one task
discovers targets another task then scans, e.g. subdomain_recon -> host_recon) and DROP the
out-of-scope discovered targets before they are actively scanned -- while an unset scope leaves CLI
behaviour unchanged (allow-all).

This exercises the real celery build+execute path in sync mode (same harness as
test_target_filter_scope / #1328): `discovertask` stands in for a recon step that DISCOVERS targets,
`consumetask` stands in for the downstream active task that resolves those discovered Targets as its
own scan inputs. The filter is applied in `run_extractors` (secator/runners/_helpers.py), the single
scan-input choke point; finding emission (the Targets a task yields) is NOT gated.
"""
import unittest
from unittest.mock import patch

from secator.decorators import task
from secator.output_types import Target
from secator.runners import Scan
from secator.runners.command import Command
from secator.template import TemplateLoader


# What each downstream (active) task resolved its scan inputs to, after scope filtering.
RESOLVED = {}

# A recon step "discovers" these: one in-scope subdomain + one out-of-scope host it found (e.g. in
# JS/HTML/a cert). Reporting it as a finding is fine; feeding it as an active-scan input is not.
DISCOVERED = ['api.acme.test', 'evil.attacker.test']


@task()
class discovertask(Command):
	"""Recon stand-in: emits discovered Targets regardless of its own inputs."""
	cmd = 'true'
	input_types = []  # accept any input
	output_types = [Target]

	def yielder(self):
		for name in DISCOVERED:
			yield Target(name=name)


@task()
class consumetask(Command):
	"""Active-task stand-in: resolves upstream discovered Targets as its scan inputs (scope filter is
	applied in _run_extractors) and records exactly what it would actively scan."""
	cmd = 'true'
	input_types = []
	output_types = [Target]

	def _run_extractors(self):
		super()._run_extractors()
		RESOLVED[self.unique_name] = sorted(self.inputs)

	def yielder(self):
		for name in self.inputs:
			yield Target(name=name)


def _wf(name, task_name, task_node, task_targets_=None):
	opts = {'targets_': task_targets_} if task_targets_ is not None else {}
	return TemplateLoader(input={
		'type': 'workflow', 'name': name,
		'tasks': {f'{task_name}/{task_node}': opts},
	})


class TestScopeInheritance(unittest.TestCase):

	ROOT = ['acme.test']  # a network root that is itself in scope (exact host)

	def setUp(self):
		"""Register the mock tasks and serve inline workflow templates by name."""
		RESOLVED.clear()
		import secator.runners.task as task_mod
		import secator.loader as loader_mod
		self._orig_discover = task_mod.discover_tasks
		task_mod.discover_tasks = lambda: list(self._orig_discover()) + [discovertask, consumetask]
		# wf1 discovers targets; wf2 (scan-level targets_) consumes them via parent_scope, which is
		# the dynamically-spawned fan-out the scope must reach.
		self._templates = [
			_wf('wf1', 'discovertask', 'recon'),
			_wf('wf2', 'consumetask', 'active', {'type': 'target', 'field': 'name'}),
		]
		self._patch_ft = patch.object(loader_mod, 'find_templates', side_effect=lambda: self._templates)
		self._patch_ft.start()

	def tearDown(self):
		import secator.runners.task as task_mod
		task_mod.discover_tasks = self._orig_discover
		self._patch_ft.stop()

	def _run(self, run_opts):
		scan_cfg = TemplateLoader(input={
			'type': 'scan', 'name': 'myscan',
			'workflows': {'wf1': {}, 'wf2': {'targets_': {'type': 'target', 'field': 'name'}}},
		})
		scan = Scan(scan_cfg, self.ROOT, run_opts={'sync': True, **run_opts}, context={})
		list(scan)
		return [inp for uname, inp in RESOLVED.items() if uname.startswith('consumetask_active')]

	def test_out_of_scope_discovered_target_is_dropped(self):
		"""in_scope inherited from the scan reaches the downstream active task and drops the
		out-of-scope discovered target before it is scanned (the linchpin)."""
		results = self._run({'in_scope': ['acme.test', '*.acme.test']})
		self.assertTrue(results, 'downstream active task never executed')
		for inputs in results:
			self.assertIn('api.acme.test', inputs)        # in-scope discovered target kept
			self.assertNotIn('evil.attacker.test', inputs)  # out-of-scope discovered target dropped

	def test_no_scope_allows_all(self):
		"""No scope set -> allow-all: CLI behaviour unchanged, out-of-scope discovered target scanned."""
		results = self._run({})
		self.assertTrue(results, 'downstream active task never executed')
		for inputs in results:
			self.assertIn('api.acme.test', inputs)
			self.assertIn('evil.attacker.test', inputs)  # nothing dropped without a scope


if __name__ == '__main__':
	unittest.main()
