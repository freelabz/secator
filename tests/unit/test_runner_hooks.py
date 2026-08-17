import pickle
import sys
import unittest

from secator.config import CONFIG
from secator.loader import discover_external_drivers
from secator.runners._base import Runner

# A minimal external driver, as a user would drop into ~/.secator/templates/.
CUSTOM_DRIVER = '''
from secator.runners import Task


def cd_on_item(self, item):
	return item


def cd_on_end(self, *args, **kwargs):
	return None


HOOKS = {Task: {'on_item': [cd_on_item], 'on_end': [cd_on_end]}}
'''


def lib_on_item(self, item):
	"""Module-level hook (picklable by qualified name), for the library-mode test."""
	return item


class TestRunnerHooks(unittest.TestCase):
	"""Driver hooks are registered once at construction and survive pickling
	natively (no __getstate__/__setstate__), so unpickling never re-registers.
	"""

	@classmethod
	def setUpClass(cls):
		# Drop the driver into the REAL templates dir (not a system tempdir): its
		# path contains '/templates/', so the coverage report's --omit=*/templates/*
		# excludes it. A tempdir path is not omitted, so coverage would later fail
		# with "No source for code" once the tempdir is gone (breaks `coverage report`).
		cls.template_dir = CONFIG.dirs.templates
		cls.template_dir.mkdir(parents=True, exist_ok=True)
		cls.driver_path = cls.template_dir / 'custom_hook_driver.py'
		cls.driver_path.write_text(CUSTOM_DRIVER)
		# discover_external_drivers is @cache'd; clear it so it re-scans and picks
		# up our driver (an earlier test/import may have populated the cache).
		discover_external_drivers.cache_clear()
		discover_external_drivers()

	@classmethod
	def tearDownClass(cls):
		if cls.driver_path.exists():
			cls.driver_path.unlink()
		sys.modules.pop('secator.hooks.custom_hook_driver', None)
		# reset the cache so later tests re-discover against the cleaned-up dir
		discover_external_drivers.cache_clear()

	def _build_task(self, **kwargs):
		# Bind the class straight from sys.modules so its identity matches what
		# pickle resolves (other suite tests may reload the task module, which
		# would otherwise make pickle reject the "not the same object" class).
		import importlib
		mod = importlib.import_module('secator.tasks.httpx')
		return mod.httpx(['http://localhost'], enable_hooks=False, dry_run=True, **kwargs)

	@staticmethod
	def _hook_names(task, event):
		return [h.__name__ for h in task.resolved_hooks[event]]

	def _count_register_hooks(self, fn):
		calls = {'n': 0}
		orig = Runner.register_hooks

		def wrapped(self, hooks):
			calls['n'] += 1
			return orig(self, hooks)

		Runner.register_hooks = wrapped
		try:
			fn()
		finally:
			Runner.register_hooks = orig
		return calls['n']

	def test_driver_hooks_loaded_at_init(self):
		# context['drivers'] hooks must be present right after construction (no pickle)
		task = self._build_task(context={'drivers': ['custom_hook_driver']})
		self.assertIn('cd_on_item', self._hook_names(task, 'on_item'))
		self.assertIn('cd_on_end', self._hook_names(task, 'on_end'))

	def test_custom_driver_hook_survives_pickle_without_reregistration(self):
		task = self._build_task(context={'drivers': ['custom_hook_driver']})
		# unpickling must NOT call register_hooks (this is what flooded the logs)
		reg = self._count_register_hooks(lambda: pickle.loads(pickle.dumps(task)))
		self.assertEqual(reg, 0, 'unpickle must not re-register hooks')
		# and the hook must still be there + callable
		back = pickle.loads(pickle.dumps(task))
		self.assertIn('cd_on_item', self._hook_names(back, 'on_item'))
		self.assertTrue(callable(back.resolved_hooks['on_item'][0]))

	def test_registration_is_idempotent(self):
		task = self._build_task(context={'drivers': ['custom_hook_driver']})
		before = len(task.resolved_hooks['on_item'])
		# re-apply the same context drivers -> no duplicate registration
		task._apply_context_drivers()
		self.assertEqual(len(task.resolved_hooks['on_item']), before)

	def test_library_mode_explicit_hooks_survive_pickle(self):
		# Library callers pass hooks explicitly and may set NO context['drivers'].
		task = self._build_task(hooks={'on_item': [lib_on_item]})
		self.assertIn('lib_on_item', self._hook_names(task, 'on_item'))
		back = pickle.loads(pickle.dumps(task))
		self.assertIn('lib_on_item', self._hook_names(back, 'on_item'))


if __name__ == '__main__':
	unittest.main()
