import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

from secator.config import CONFIG
from secator.utils_test import FIXTURES_DIR, clear_modules

DRIVER_FIXTURE = Path(FIXTURES_DIR) / 'test_driver.py'
EXPORTER_FIXTURE = Path(FIXTURES_DIR) / 'test_exporter.py'


def _clear_loader_caches():
    """Clear @cache results for all loader discovery functions."""
    from secator import loader
    for name in [
        'discover_external_drivers',
        'discover_external_exporters',
        'discover_external_tasks',
        'discover_tasks',
        'get_available_drivers',
        'get_available_exporters',
        'find_templates',
        'get_configs_by_type',
        'load_external_addons',
    ]:
        fn = getattr(loader, name, None)
        if fn and hasattr(fn, 'cache_clear'):
            fn.cache_clear()


class TestFileDetectionHelpers(unittest.TestCase):
    """Unit tests for _file_has_hooks and _file_has_exporter."""

    def setUp(self):
        self.template_dir = CONFIG.dirs.templates
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self._tmp = []

    def tearDown(self):
        for f in self._tmp:
            if f.exists():
                f.unlink()

    def _tmp_file(self, name, content):
        path = self.template_dir / name
        path.write_text(content)
        self._tmp.append(path)
        return path

    def test_file_has_hooks_true(self):
        from secator.loader import _file_has_hooks
        f = self._tmp_file('hooks_yes.py', 'HOOKS = {}\n')
        self.assertTrue(_file_has_hooks(f))

    def test_file_has_hooks_no_space_true(self):
        from secator.loader import _file_has_hooks
        f = self._tmp_file('hooks_nospace.py', 'HOOKS={}\n')
        self.assertTrue(_file_has_hooks(f))

    def test_file_has_hooks_false(self):
        from secator.loader import _file_has_hooks
        f = self._tmp_file('hooks_no.py', 'class Foo:\n    pass\n')
        self.assertFalse(_file_has_hooks(f))

    def test_file_has_hooks_nonexistent_returns_false(self):
        from secator.loader import _file_has_hooks
        self.assertFalse(_file_has_hooks(self.template_dir / 'missing_file.py'))

    def test_file_has_exporter_true(self):
        from secator.loader import _file_has_exporter
        f = self._tmp_file('exp_yes.py', 'class Foo(Exporter):\n    pass\n')
        self.assertTrue(_file_has_exporter(f))

    def test_file_has_exporter_false(self):
        from secator.loader import _file_has_exporter
        f = self._tmp_file('exp_no.py', 'class Foo:\n    pass\n')
        self.assertFalse(_file_has_exporter(f))

    def test_file_has_exporter_nonexistent_returns_false(self):
        from secator.loader import _file_has_exporter
        self.assertFalse(_file_has_exporter(self.template_dir / 'missing_file.py'))


class TestDiscoverExternalDrivers(unittest.TestCase):
    """Tests for discover_external_drivers."""

    def setUp(self):
        self.template_dir = CONFIG.dirs.templates
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.driver_path = self.template_dir / 'test_driver.py'
        clear_modules()
        _clear_loader_caches()

    def tearDown(self):
        if self.driver_path.exists():
            self.driver_path.unlink()
        for key in list(sys.modules.keys()):
            if 'secator.hooks.test_driver' in key:
                del sys.modules[key]
        _clear_loader_caches()

    def test_valid_driver_is_discovered(self):
        """Driver file with HOOKS dict is picked up by discover_external_drivers."""
        shutil.copyfile(DRIVER_FIXTURE, self.driver_path)
        from secator.loader import discover_external_drivers
        result = discover_external_drivers()
        self.assertIn('test_driver', result)

    def test_no_driver_files_returns_empty(self):
        """No driver files in the templates dir → driver not in result."""
        from secator.loader import discover_external_drivers
        result = discover_external_drivers()
        self.assertNotIn('test_driver', result)

    def test_driver_missing_hooks_attribute_is_skipped(self):
        """File whose text matches 'HOOKS =' but deletes the attribute at runtime is skipped."""
        path = self.template_dir / 'hookless.py'
        path.write_text('HOOKS = {}\ndel HOOKS\n')
        try:
            from secator.loader import discover_external_drivers
            discover_external_drivers.cache_clear()
            result = discover_external_drivers()
            self.assertNotIn('hookless', result)
        finally:
            if path.exists():
                path.unlink()
            for key in list(sys.modules.keys()):
                if 'hookless' in key:
                    del sys.modules[key]

    def test_returns_list(self):
        """discover_external_drivers always returns a list."""
        from secator.loader import discover_external_drivers
        self.assertIsInstance(discover_external_drivers(), list)

    def test_result_is_cached(self):
        """Calling discover_external_drivers twice returns the same list object."""
        shutil.copyfile(DRIVER_FIXTURE, self.driver_path)
        from secator.loader import discover_external_drivers
        self.assertIs(discover_external_drivers(), discover_external_drivers())


class TestDiscoverExternalExporters(unittest.TestCase):
    """Tests for discover_external_exporters."""

    def setUp(self):
        self.template_dir = CONFIG.dirs.templates
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.exporter_path = self.template_dir / 'test_exporter.py'
        clear_modules()
        _clear_loader_caches()

    def tearDown(self):
        if self.exporter_path.exists():
            self.exporter_path.unlink()
        for key in list(sys.modules.keys()):
            if 'secator.exporters.test_exporter' in key:
                del sys.modules[key]
        try:
            import secator.exporters as pkg
            if hasattr(pkg, 'TestExporter'):
                delattr(pkg, 'TestExporter')
        except Exception:
            pass
        _clear_loader_caches()

    def test_valid_exporter_is_discovered(self):
        """Exporter file with an Exporter subclass is picked up."""
        shutil.copyfile(EXPORTER_FIXTURE, self.exporter_path)
        from secator.loader import discover_external_exporters
        result = discover_external_exporters()
        # TestExporter → 'testexporter'[:-8] = 'test'
        self.assertIn('test', result)

    def test_exporter_registered_on_package(self):
        """Discovered exporter class is set as attribute on secator.exporters."""
        shutil.copyfile(EXPORTER_FIXTURE, self.exporter_path)
        from secator.loader import discover_external_exporters
        discover_external_exporters()
        import secator.exporters as pkg
        self.assertTrue(hasattr(pkg, 'TestExporter'))

    def test_no_exporter_files_returns_empty(self):
        """No exporter files in the templates dir → exporter not in result."""
        from secator.loader import discover_external_exporters
        result = discover_external_exporters()
        self.assertNotIn('test', result)

    def test_file_with_exporter_only_in_comment_is_skipped(self):
        """File with '(Exporter)' only in a comment and no real subclass is skipped."""
        path = self.template_dir / 'commented_exp.py'
        # The text contains '(Exporter)' to pass the fast check, but no real subclass
        path.write_text('# class Foo(Exporter): - this is just a comment\nclass Foo:\n    pass\n')
        try:
            from secator.loader import discover_external_exporters
            discover_external_exporters.cache_clear()
            result = discover_external_exporters()
            self.assertNotIn('commented_exp', result)
        finally:
            if path.exists():
                path.unlink()
            for key in list(sys.modules.keys()):
                if 'commented_exp' in key:
                    del sys.modules[key]

    def test_returns_list(self):
        """discover_external_exporters always returns a list."""
        from secator.loader import discover_external_exporters
        self.assertIsInstance(discover_external_exporters(), list)

    def test_result_is_cached(self):
        """Calling discover_external_exporters twice returns the same list object."""
        shutil.copyfile(EXPORTER_FIXTURE, self.exporter_path)
        from secator.loader import discover_external_exporters
        self.assertIs(discover_external_exporters(), discover_external_exporters())


class TestGetAvailableDrivers(unittest.TestCase):
    """Tests for get_available_drivers."""

    def setUp(self):
        _clear_loader_caches()

    def tearDown(self):
        _clear_loader_caches()

    def test_includes_all_internal_drivers(self):
        """Every entry in AVAILABLE_DRIVERS appears in get_available_drivers()."""
        from secator.loader import get_available_drivers
        from secator.definitions import AVAILABLE_DRIVERS
        result = get_available_drivers()
        for driver in AVAILABLE_DRIVERS:
            self.assertIn(driver, result)

    def test_appends_external_drivers(self):
        """External drivers returned by discover_external_drivers appear in the result."""
        from secator.loader import get_available_drivers
        with mock.patch('secator.loader.discover_external_drivers', return_value=['ext_driver']):
            get_available_drivers.cache_clear()
            result = get_available_drivers()
        self.assertIn('ext_driver', result)

    def test_no_duplicates(self):
        """Result list contains no duplicate entries."""
        from secator.loader import get_available_drivers
        result = get_available_drivers()
        self.assertEqual(len(result), len(set(result)))

    def test_returns_list(self):
        """get_available_drivers returns a list."""
        from secator.loader import get_available_drivers
        self.assertIsInstance(get_available_drivers(), list)

    def test_empty_external_returns_only_internal(self):
        """When no external drivers exist, result equals AVAILABLE_DRIVERS."""
        from secator.loader import get_available_drivers
        from secator.definitions import AVAILABLE_DRIVERS
        with mock.patch('secator.loader.discover_external_drivers', return_value=[]):
            get_available_drivers.cache_clear()
            result = get_available_drivers()
        self.assertEqual(sorted(result), sorted(AVAILABLE_DRIVERS))


class TestGetAvailableExporters(unittest.TestCase):
    """Tests for get_available_exporters."""

    def setUp(self):
        _clear_loader_caches()

    def tearDown(self):
        _clear_loader_caches()

    def test_includes_all_internal_exporters(self):
        """Every entry in AVAILABLE_EXPORTERS appears in get_available_exporters()."""
        from secator.loader import get_available_exporters
        from secator.definitions import AVAILABLE_EXPORTERS
        result = get_available_exporters()
        for exporter in AVAILABLE_EXPORTERS:
            self.assertIn(exporter, result)

    def test_appends_external_exporters(self):
        """External exporters returned by discover_external_exporters appear in the result."""
        from secator.loader import get_available_exporters
        with mock.patch('secator.loader.discover_external_exporters', return_value=['ext_exp']):
            get_available_exporters.cache_clear()
            result = get_available_exporters()
        self.assertIn('ext_exp', result)

    def test_no_duplicates(self):
        """Result list contains no duplicate entries."""
        from secator.loader import get_available_exporters
        result = get_available_exporters()
        self.assertEqual(len(result), len(set(result)))

    def test_returns_list(self):
        """get_available_exporters returns a list."""
        from secator.loader import get_available_exporters
        self.assertIsInstance(get_available_exporters(), list)

    def test_empty_external_returns_only_internal(self):
        """When no external exporters exist, result equals AVAILABLE_EXPORTERS."""
        from secator.loader import get_available_exporters
        from secator.definitions import AVAILABLE_EXPORTERS
        with mock.patch('secator.loader.discover_external_exporters', return_value=[]):
            get_available_exporters.cache_clear()
            result = get_available_exporters()
        self.assertEqual(sorted(result), sorted(AVAILABLE_EXPORTERS))


class TestLoadExternalAddons(unittest.TestCase):
    """Tests for load_external_addons."""

    def setUp(self):
        self.template_dir = CONFIG.dirs.templates
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.addons_file = self.template_dir / 'addons.json'
        _clear_loader_caches()

    def tearDown(self):
        if self.addons_file.exists():
            self.addons_file.unlink()
        _clear_loader_caches()

    def _write_addons(self, data):
        import json
        self.addons_file.write_text(json.dumps(data))

    def test_returns_empty_dict_when_file_absent(self):
        """No addons.json → empty dict returned."""
        from secator.loader import load_external_addons
        result = load_external_addons()
        self.assertEqual(result, {})

    def test_returns_dict_with_pypi_addon(self):
        """Valid addons.json with pypi_dependencies is loaded correctly."""
        self._write_addons({
            'elasticsearch': {
                'pypi_dependencies': ['elasticsearch<10'],
                'next_steps': [],
            }
        })
        from secator.loader import load_external_addons
        result = load_external_addons()
        self.assertIn('elasticsearch', result)
        self.assertEqual(result['elasticsearch']['pypi_dependencies'], ['elasticsearch<10'])

    def test_returns_dict_with_tool_addon(self):
        """Valid addons.json with tool install fields is loaded correctly."""
        self._write_addons({
            'my_tool': {
                'install_cmd': 'curl https://example.com/install.sh | sh',
                'install_version': '1.0.0',
            }
        })
        from secator.loader import load_external_addons
        result = load_external_addons()
        self.assertIn('my_tool', result)
        self.assertEqual(result['my_tool']['install_version'], '1.0.0')

    def test_returns_empty_dict_on_invalid_json(self):
        """Malformed addons.json returns empty dict and does not raise."""
        self.addons_file.write_text('not valid json {{{')
        from secator.loader import load_external_addons
        result = load_external_addons()
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_root_is_not_object(self):
        """addons.json containing a JSON array (not an object) returns empty dict."""
        self._write_addons([{'pypi_dependencies': ['pkg']}])
        from secator.loader import load_external_addons
        result = load_external_addons()
        self.assertEqual(result, {})

    def test_result_is_cached(self):
        """Calling load_external_addons twice returns the same dict object."""
        self._write_addons({'myaddon': {'pypi_dependencies': ['mypkg']}})
        from secator.loader import load_external_addons
        self.assertIs(load_external_addons(), load_external_addons())

    def test_returns_dict_type(self):
        """load_external_addons always returns a dict."""
        from secator.loader import load_external_addons
        self.assertIsInstance(load_external_addons(), dict)

    def test_filters_out_non_dict_addon_entries(self):
        """Addon entries with non-dict values are excluded; valid entries are still returned."""
        self._write_addons({
            'bad_addon': 'not-an-object',
            'good_addon': {'install_cmd': 'echo install'},
        })
        from secator.loader import load_external_addons
        result = load_external_addons()
        self.assertNotIn('bad_addon', result)
        self.assertIn('good_addon', result)


class TestDiscoverExternalTasksSkipsDriversAndExporters(unittest.TestCase):
    """discover_external_tasks must not attempt to load driver or exporter files."""

    def setUp(self):
        self.template_dir = CONFIG.dirs.templates
        self.template_dir.mkdir(parents=True, exist_ok=True)
        clear_modules()
        _clear_loader_caches()

    def tearDown(self):
        for path in self.template_dir.glob('skiptest_*.py'):
            path.unlink()
        for key in list(sys.modules.keys()):
            if 'skiptest_' in key:
                del sys.modules[key]
        _clear_loader_caches()

    def test_driver_files_not_loaded_as_tasks(self):
        """Files containing 'HOOKS =' are excluded from task discovery."""
        path = self.template_dir / 'skiptest_driver.py'
        path.write_text('HOOKS = {}\n')
        from secator.loader import discover_external_tasks
        result = discover_external_tasks()
        result_names = [cls.__name__ for cls in result]
        self.assertNotIn('skiptest_driver', result_names)

    def test_driver_files_hooks_no_space_not_loaded_as_tasks(self):
        """Files containing 'HOOKS=' (no space) are excluded from task discovery."""
        path = self.template_dir / 'skiptest_nospace.py'
        path.write_text('HOOKS={}\n')
        from secator.loader import discover_external_tasks
        result = discover_external_tasks()
        result_names = [cls.__name__ for cls in result]
        self.assertNotIn('skiptest_nospace', result_names)

    def test_exporter_files_not_loaded_as_tasks(self):
        """Files containing '(Exporter)' are excluded from task discovery."""
        path = self.template_dir / 'skiptest_exporter.py'
        path.write_text('class SkipTestExporter(Exporter):\n    pass\n')
        from secator.loader import discover_external_tasks
        result = discover_external_tasks()
        result_names = [cls.__name__ for cls in result]
        self.assertNotIn('SkipTestExporter', result_names)

    def test_non_class_task_attribute_not_loaded(self):
        """Files where the task attribute is not a class are excluded from task discovery."""
        path = self.template_dir / 'skiptest_nonclass.py'
        # The file has an attribute with the module's own name but it's not a class
        path.write_text('skiptest_nonclass = "not a class"\n')
        from secator.loader import discover_external_tasks
        result = discover_external_tasks()
        result_names = [cls.__name__ for cls in result]
        self.assertNotIn('skiptest_nonclass', result_names)


if __name__ == '__main__':
    unittest.main()
