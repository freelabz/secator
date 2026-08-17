import os
import shutil
import sys
import tempfile

from secator.config import CONFIG

# Canonical secator.* module generation, captured lazily at the first test's setup (once collection
# has imported every test file, so their module-level class refs — `from secator.output_types import
# Error`, etc. — are bound to THIS generation). Several tests call clear_modules() to exercise
# fresh-import behaviour, which purges these and lets a SECOND generation load lazily; a finding
# produced by a collection-time runner then fails an identity check against the fresh generation
# (dataclass __eq__ compares by class → spurious assertIn/== failures, and driver store writes get
# silently dropped). Restoring this snapshot after every test heals any such purge.
_SECATOR_MODULES = None

# json is the core default store, so every unit test's runners write report.json. Point the reports
# dir at ONE stable tmp path for the whole session (set at import, before any runner is built, and
# via env so it survives clear_modules() reloads). A single dir is safe: results are scoped by the
# runner's UUID {type}_id, so each test's view sees only its own findings even in a shared dir. A
# per-test dir would break — reports_folder caches at construction and clear_modules() freezes the
# reloaded CONFIG, so per-test dir swaps don't reach the runner's CONFIG (write/read mismatch).
_REPORTS = tempfile.mkdtemp(prefix='secator_unit_reports_')
os.environ['SECATOR_DIRS_REPORTS'] = _REPORTS
CONFIG.dirs.reports = _REPORTS


def pytest_runtest_setup(item):
	global _SECATOR_MODULES
	if _SECATOR_MODULES is None:  # first test: collection done, class refs bound to this generation
		_SECATOR_MODULES = {k: v for k, v in sys.modules.items() if k.startswith('secator')}
	# test_config asserts the default dir resolution — opt it out of the global reports override.
	if 'test_config' in str(item.fspath):
		os.environ.pop('SECATOR_DIRS_REPORTS', None)
		return
	# test_config's clear_modules() reloads the CONFIG singleton (leaving dirs.reports at its default),
	# and that reloaded object persists for later tests. Re-pin it to _REPORTS before every other test so
	# runners write and the StreamView reads the same store dir.
	os.environ['SECATOR_DIRS_REPORTS'] = _REPORTS
	from secator.config import CONFIG as _CFG
	_CFG.dirs.reports = _REPORTS


def pytest_runtest_teardown(item):
	if 'test_config' in str(item.fspath):
		os.environ['SECATOR_DIRS_REPORTS'] = _REPORTS
	# Heal any clear_modules() the test performed: purge the (possibly second-generation) secator
	# modules and restore the collection-time objects, so the next test's runners, drivers and
	# OutputType classes are all the one generation the test files hold references to. Only do this
	# when the generation actually changed (sentinel identity) — otherwise we'd also evict modules a
	# well-behaved test merely imported (e.g. a dynamically-discovered external driver), leaving
	# discover_external_drivers' @cache pointing at a now-missing module.
	if _SECATOR_MODULES is not None and \
			sys.modules.get('secator.output_types') is not _SECATOR_MODULES.get('secator.output_types'):
		for k in [k for k in sys.modules if k.startswith('secator')]:
			del sys.modules[k]
		sys.modules.update(_SECATOR_MODULES)


def pytest_sessionfinish(session, exitstatus):
	shutil.rmtree(_REPORTS, ignore_errors=True)
