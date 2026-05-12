"""
Tests for fix of issue #1070: subsequent workflow tasks in scan not defaulting to original targets.

Design: Approach B — scope-tagged Target emission from mark_runner_started.
"""
import unittest
from unittest.mock import patch

from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, URL
from secator.output_types import Port, Tag, Target, Technology, Url
from secator.runners import PythonRunner
from secator.runners._helpers import process_extractor, run_extractors
from secator.template import TemplateLoader

# --- Mock tasks (record inputs for assertions) ---

MOCK_INPUTS = {}


@task()
class w1_1(PythonRunner):
    """HOST → Port (ports 80, 443, 445)."""
    input_types = [HOST]
    output_types = [Port]

    def yielder(self):
        MOCK_INPUTS['w1_1'] = sorted(self.inputs)
        for target in self.inputs:
            yield Port(ip=target, host=target, port=80, protocol='tcp')
            yield Port(ip=target, host=target, port=443, protocol='tcp')
            yield Port(ip=target, host=target, port=445, protocol='tcp')


@task()
class w1_2(PythonRunner):
    """URL → Technology."""
    input_types = [URL]
    output_types = [Technology]

    def yielder(self):
        MOCK_INPUTS['w1_2'] = sorted(self.inputs)
        for target in self.inputs:
            yield Technology(match=target, product='Apache', version='2.4')


@task()
class w2_1(PythonRunner):
    """HOST_PORT containing '445' → Tag(category='secret')."""
    input_types = [HOST_PORT]
    output_types = [Tag]

    def yielder(self):
        MOCK_INPUTS['w2_1'] = sorted(self.inputs)
        for target in self.inputs:
            yield Tag(name='smb', match=target, category='secret')


@task()
class w2_2(PythonRunner):
    """All HOST_PORT targets → Url(status_code=200)."""
    input_types = [HOST_PORT]
    output_types = [Url]

    def yielder(self):
        MOCK_INPUTS['w2_2'] = sorted(self.inputs)
        for target in self.inputs:
            yield Url(url=f'http://{target}', status_code=200)


@task()
class w2_3(PythonRunner):
    """Tag(secret) + Url(200) → Tag(verified)."""
    input_types = [HOST_PORT, URL]
    output_types = [Tag]

    def yielder(self):
        MOCK_INPUTS['w2_3'] = sorted(self.inputs)
        for target in self.inputs:
            yield Tag(name='found-secret', match=target, category='verified')


MOCK_TASK_CLASSES = [w1_1, w1_2, w2_1, w2_2, w2_3]


# --- In-memory configs ---

def make_workflow1_config():
    return TemplateLoader(input={
        'name': 'workflow1',
        'type': 'workflow',
        'input_types': ['url', 'host'],
        'tasks': {
            'w1_1': {
                'targets_': [
                    {'type': 'target', 'field': 'name', 'condition': "target.type == 'host'"}
                ]
            },
            'w1_2': {
                'targets_': [
                    {'type': 'target', 'field': 'name', 'condition': "target.type == 'url'"}
                ]
            },
        }
    })


def make_workflow2_config():
    return TemplateLoader(input={
        'name': 'workflow2',
        'type': 'workflow',
        'input_types': ['host:port'],
        'tasks': {
            'w2_1': {
                'targets_': [
                    {'type': 'target', 'field': 'name', 'condition': "'445' in target.name"}
                ]
            },
            'w2_2': {},
            'w2_3': {
                'targets_': [
                    {'type': 'tag', 'field': 'match', 'condition': "tag.category == 'secret'"},
                    {'type': 'url', 'field': 'url', 'condition': 'url.status_code == 200'},
                ]
            },
        }
    })


def make_scan_config():
    return TemplateLoader(input={
        'name': 'test_scan',
        'type': 'scan',
        'input_types': ['url', 'host'],
        'workflows': {
            'workflow1': {},
            'workflow2': {
                'targets_': [
                    {'type': 'port', 'field': '{host}:{port}'}
                ]
            },
        }
    })


def patched_discover_tasks():
    """Return only mock task classes (avoids slow real task discovery in unit tests)."""
    return MOCK_TASK_CLASSES


def patched_find_templates():
    """Return in-memory workflow/scan configs."""
    return [make_workflow1_config(), make_workflow2_config(), make_scan_config()]


def get_all_task_opts(sig):
    """Recursively extract opts dicts from all run_command sigs in a chain/group."""
    opts_list = []
    if hasattr(sig, 'tasks'):        # chain
        for subtask in sig.tasks:
            opts_list.extend(get_all_task_opts(subtask))
    elif hasattr(sig, 'kwargs') and 'opts' in sig.kwargs:
        opts_list.append(sig.kwargs['opts'])
    return opts_list


class TestProcessExtractorScopeFiltering(unittest.TestCase):
    """process_extractor must use scope-based filtering for type='target' when parent_scope is set."""

    def _make_scope_target(self, name, scope):
        t = Target(name=name)
        t._context['scope'] = scope
        return t

    def test_scope_filter_finds_matching_targets(self):
        """Targets tagged with parent_scope must be returned by the extractor."""
        t_in = self._make_scope_target('example.com:445', 'workflow2')
        t_out = self._make_scope_target('other.com:80', 'workflow1')
        plain = Target(name='plain.com')
        results = [t_in, t_out, plain]

        extractor = {'type': 'target', 'field': 'name'}
        ctx = {'key': 'targets', 'parent_scope': 'workflow2', 'ancestor_id': 'workflow2', 'node_chain_start': False}
        extracted = process_extractor(results, extractor, ctx=ctx)

        self.assertIn('example.com:445', extracted)
        self.assertNotIn('other.com:80', extracted)
        self.assertNotIn('plain.com', extracted)

    def test_scope_filter_with_condition(self):
        """Scope + condition must both be satisfied."""
        t_445 = self._make_scope_target('example.com:445', 'workflow2')
        t_80 = self._make_scope_target('example.com:80', 'workflow2')
        results = [t_445, t_80]

        extractor = {'type': 'target', 'field': 'name', 'condition': "'445' in target.name"}
        ctx = {'key': 'targets', 'parent_scope': 'workflow2', 'ancestor_id': 'workflow2', 'node_chain_start': False}
        extracted = process_extractor(results, extractor, ctx=ctx)

        self.assertEqual(extracted, ['example.com:445'])

    def test_no_parent_scope_falls_back_to_ancestor_id(self):
        """Without parent_scope, ancestor_id filtering must still apply (no regression)."""
        t_right = Target(name='example.com')
        t_right._context['ancestor_id'] = 'wf-abc'
        t_wrong = Target(name='other.com')
        t_wrong._context['ancestor_id'] = 'wf-xyz'
        results = [t_right, t_wrong]

        extractor = {'type': 'target', 'field': 'name'}
        ctx = {'key': 'targets', 'ancestor_id': 'wf-abc', 'node_chain_start': False}
        extracted = process_extractor(results, extractor, ctx=ctx)

        self.assertIn('example.com', extracted)
        self.assertNotIn('other.com', extracted)

    def test_node_chain_start_skips_ancestor_id_for_non_target(self):
        """node_chain_start=True must skip ancestor_id filtering for non-target types."""
        u1 = Url(url='http://example.com')
        u1._context['ancestor_id'] = 'wf-other'
        u2 = Url(url='http://other.com')
        u2._context['ancestor_id'] = 'wf-abc'
        results = [u1, u2]

        extractor = {'type': 'url', 'field': 'url'}
        ctx = {'key': 'targets', 'ancestor_id': 'wf-abc', 'node_chain_start': True}
        extracted = process_extractor(results, extractor, ctx=ctx)

        self.assertIn('http://example.com', extracted)
        self.assertIn('http://other.com', extracted)


class TestRunExtractorsScopeFallback(unittest.TestCase):
    """run_extractors must fall back to scope-tagged Targets when no targets_ extractor + parent_scope set."""

    def _make_scope_target(self, name, scope):
        t = Target(name=name)
        t._context['scope'] = scope
        return t

    def test_fallback_to_scoped_targets_when_no_extractor(self):
        """When no targets_ extractor and parent_scope is set, use scope-tagged Targets."""
        t1 = self._make_scope_target('example.com:80', 'workflow2')
        t2 = self._make_scope_target('example.com:445', 'workflow2')
        t_other = self._make_scope_target('other.com:80', 'workflow1')
        results = [t1, t2, t_other]

        inputs, _, errors = run_extractors(
            results, {},
            inputs=['original.com'],
            ctx={'parent_scope': 'workflow2'}
        )
        self.assertEqual(errors, [])
        self.assertIn('example.com:80', inputs)
        self.assertIn('example.com:445', inputs)
        self.assertNotIn('other.com:80', inputs)
        self.assertNotIn('original.com', inputs)

    def test_fallback_preserves_original_inputs_when_no_scoped_targets(self):
        """If parent_scope set but no matching scope targets and no ancestor_id results, keep original inputs."""
        unscoped = Target(name='other.com')
        results = [unscoped]

        inputs, _, errors = run_extractors(
            results, {},
            inputs=['original.com'],
            ctx={'parent_scope': 'workflow2'}
        )
        self.assertEqual(errors, [])
        self.assertEqual(inputs, ['original.com'])

    def test_no_fallback_without_parent_scope(self):
        """Without parent_scope, scope fallback must not activate (no regression)."""
        t = Target(name='example.com')
        t._context['scope'] = 'workflow2'
        t._context['ancestor_id'] = 'workflow2'
        results = [t]

        inputs, _, errors = run_extractors(
            results, {},
            inputs=['original.com'],
            ctx={}
        )
        self.assertEqual(errors, [])
        self.assertEqual(inputs, ['original.com'])

    def test_explicit_targets_extractor_overrides_fallback(self):
        """When a targets_ extractor IS present, it must win over scope fallback."""
        t = Target(name='scope.com:80')
        t._context['scope'] = 'workflow2'
        url = Url(url='http://extracted.com')
        results = [t, url]

        inputs, _, errors = run_extractors(
            results,
            {'targets_': [{'type': 'url', 'field': 'url'}]},
            inputs=['original.com'],
            ctx={'parent_scope': 'workflow2'}
        )
        self.assertEqual(errors, [])
        self.assertIn('http://extracted.com', inputs)
        self.assertNotIn('scope.com:80', inputs)

    def test_chunk_task_scope_fallback_not_applied(self):
        """Chunked sub-tasks must keep their pre-determined input, not be overridden by scope fallback.

        Regression test for: break_task removes targets_ from opts, causing scope fallback to fire
        and replace the chunk's single input with all scope-tagged targets (issue #1070 follow-up).
        """
        t1 = self._make_scope_target('host1.com', 'workflow2')
        t2 = self._make_scope_target('host2.com', 'workflow2')
        results = [t1, t2]
        chunk_query = 'nginx 1.18.0~host1.com,host2.com'

        # opts has no targets_ (break_task removes it) but has chunk=1 and parent_scope
        inputs, _, errors = run_extractors(
            results,
            {'parent_scope': 'workflow2', 'chunk': 1},
            inputs=[chunk_query],
            ctx={'parent_scope': 'workflow2'}
        )
        self.assertEqual(errors, [])
        self.assertEqual(inputs, [chunk_query],
            "Chunk input must not be overridden by scope fallback")


class TestBuildCeleryWorkflowContext(unittest.TestCase):
    """build_celery_workflow must set parent_scope, ancestor_id, node_chain_start correctly."""

    def _build_workflow2_chain(self, chain_previous_results):
        from secator.runners import Workflow
        config = make_workflow2_config()
        targets_extractor = [{'type': 'port', 'field': '{host}:{port}'}]
        run_opts = {
            'targets_': targets_extractor,
            'has_parent': True,
            'skip_if_no_inputs': True,
            'caller': 'Scan',
        }
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            wf = Workflow(config, inputs=[], run_opts=run_opts)
            return wf, wf.build_celery_workflow(chain_previous_results=chain_previous_results)

    def test_all_tasks_have_parent_scope_when_chain_with_targets_extractor(self):
        """All tasks must have parent_scope='workflow2' when chain_previous_results=True and targets_ set."""
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            wf, chain_sig = self._build_workflow2_chain(chain_previous_results=True)
            all_opts = get_all_task_opts(chain_sig)
            task_opts_list = [o for o in all_opts if o.get('name') in ('w2_1', 'w2_2', 'w2_3')]
            self.assertGreaterEqual(len(task_opts_list), 3)
            for opts in task_opts_list:
                self.assertEqual(opts.get('parent_scope'), 'workflow2',
                    f"Task {opts.get('name')} missing parent_scope='workflow2'")

    def test_all_tasks_have_ancestor_id_set(self):
        """All tasks must have ancestor_id set to current_id (not None)."""
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            _, chain_sig = self._build_workflow2_chain(chain_previous_results=True)
            all_opts = get_all_task_opts(chain_sig)
            task_opts_list = [o for o in all_opts if o.get('name') in ('w2_1', 'w2_2', 'w2_3')]
            for opts in task_opts_list:
                ctx = opts.get('context', {})
                self.assertIsNotNone(ctx.get('ancestor_id'),
                    f"Task {opts.get('name')} has None ancestor_id")

    def test_first_task_has_node_chain_start_true(self):
        """First task in chain must have node_chain_start=True."""
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            _, chain_sig = self._build_workflow2_chain(chain_previous_results=True)
            all_opts = get_all_task_opts(chain_sig)
            task_opts_list = [o for o in all_opts if o.get('name') in ('w2_1', 'w2_2', 'w2_3')]
            self.assertTrue(task_opts_list[0].get('node_chain_start'),
                "First task must have node_chain_start=True")

    def test_subsequent_tasks_have_node_chain_start_false(self):
        """Subsequent tasks (ix > 0) must have node_chain_start=False."""
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            _, chain_sig = self._build_workflow2_chain(chain_previous_results=True)
            all_opts = get_all_task_opts(chain_sig)
            task_opts_list = [o for o in all_opts if o.get('name') in ('w2_1', 'w2_2', 'w2_3')]
            for opts in task_opts_list[1:]:
                self.assertFalse(opts.get('node_chain_start'),
                    f"Task {opts.get('name')} (non-first) should have node_chain_start=False")

    def test_no_targets_extractor_forwarded_to_tasks(self):
        """Scan-level targets_ (port type) must NOT appear in individual task opts."""
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            _, chain_sig = self._build_workflow2_chain(chain_previous_results=True)
            all_opts = get_all_task_opts(chain_sig)
            # w2_2 has no task-level targets_ extractor, so it must not have targets_ at all
            w2_2_opts_list = [o for o in all_opts if o.get('name') == 'w2_2']
            self.assertGreaterEqual(len(w2_2_opts_list), 1, "w2_2 opts not found in chain")
            for opts in w2_2_opts_list:
                self.assertNotIn('targets_', opts,
                    f"Task w2_2 must not receive scan-level targets_ extractor")
            # For tasks that DO have task-level extractors (w2_1, w2_3), verify the scan-level
            # port extractor is NOT forwarded (only their own task-level extractors should appear)
            scan_level_extractor = {'type': 'port', 'field': '{host}:{port}'}
            for opts in [o for o in all_opts if o.get('name') in ('w2_1', 'w2_3')]:
                task_extractors = opts.get('targets_', [])
                for ext in (task_extractors if isinstance(task_extractors, list) else [task_extractors]):
                    if hasattr(ext, 'toDict'):
                        ext = ext.toDict()
                    self.assertNotEqual(ext.get('type'), 'port',
                        f"Task {opts.get('name')} received scan-level port targets_ extractor")

    def test_no_parent_scope_without_targets_extractor(self):
        """Without a scan-level targets_ extractor, parent_scope must NOT be set."""
        from secator.runners import Workflow
        config = make_workflow2_config()
        run_opts = {'has_parent': True, 'skip_if_no_inputs': True, 'caller': 'Scan'}
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            wf = Workflow(config, inputs=['example.com'], run_opts=run_opts)
            chain_sig = wf.build_celery_workflow(chain_previous_results=True)
            all_opts = get_all_task_opts(chain_sig)
            task_opts_list = [o for o in all_opts if o.get('name') in ('w2_1', 'w2_2', 'w2_3')]
            for opts in task_opts_list:
                self.assertIsNone(opts.get('parent_scope'),
                    f"Task {opts.get('name')} must not have parent_scope when no scan-level targets_ extractor")


class TestMarkRunnerStartedScopeEmission(unittest.TestCase):
    """mark_runner_started must emit scope-tagged Targets when workflow has parent_scope + targets_ extractor."""

    def setUp(self):
        # Ensure clean secator module state (guard against clear_modules() from test_runners.py)
        from secator.utils_test import clear_modules
        clear_modules()

    def _make_port(self, ip, port):
        import uuid as _uuid
        from secator.output_types import Port as _Port  # fresh import after any clear_modules
        p = _Port(ip=ip, host=ip, port=port, protocol='tcp')
        p._uuid = str(_uuid.uuid4())
        return p

    def _build_workflow2_runner(self, prior_results):
        """Build a workflow2 runner as if it was set up by the scan."""
        from secator.runners import Workflow
        config = make_workflow2_config()
        run_opts = {
            'targets_': [{'type': 'port', 'field': '{host}:{port}'}],
            'has_parent': True,
            'skip_if_no_inputs': True,
            'caller': 'Scan',
        }
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            wf = Workflow(config, inputs=[], results=prior_results, run_opts=run_opts)
        wf.context['parent_scope'] = 'workflow2'
        return wf

    def test_scope_tagged_targets_emitted_when_parent_scope_set(self):
        """mark_runner_started must emit Target objects with scope='workflow2' from Port results."""
        from secator.celery import mark_runner_started
        prior_ports = [
            self._make_port('example.com', 80),
            self._make_port('example.com', 443),
            self._make_port('example.com', 445),
        ]
        wf = self._build_workflow2_runner(prior_results=[])

        result = mark_runner_started(prior_ports, wf, enable_hooks=False)

        scoped_targets = [
            r for r in result
            if r._type == 'target' and r._context.get('scope') == 'workflow2'
        ]
        scoped_names = [t.name for t in scoped_targets]
        self.assertIn('example.com:80', scoped_names)
        self.assertIn('example.com:443', scoped_names)
        self.assertIn('example.com:445', scoped_names)

    def test_no_scope_emission_without_parent_scope(self):
        """Without parent_scope in runner context, no scope-tagged Targets must be emitted."""
        from secator.celery import mark_runner_started
        from secator.runners import Workflow
        config = make_workflow2_config()
        run_opts = {'has_parent': True, 'caller': 'Scan'}
        with patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            wf = Workflow(config, inputs=['example.com'], run_opts=run_opts)

        prior_ports = [self._make_port('example.com', 80)]
        result = mark_runner_started(prior_ports, wf, enable_hooks=False)

        scoped_targets = [
            r for r in result
            if r._type == 'target' and r._context.get('scope') is not None
        ]
        self.assertEqual(len(scoped_targets), 0)


class TestEndToEndTargetFilteringChain(unittest.TestCase):
    """Full scan → workflow1 → workflow2 chain: verify each task receives correct inputs."""

    def setUp(self):
        MOCK_INPUTS.clear()
        # test_runners.py calls clear_modules() which wipes all secator.* from sys.modules
        # and re-imports them, causing class identity mismatches. Our module-level mock task
        # classes inherit from stale PythonRunner, breaking Celery pickle in eager mode.
        # Fix: clear secator modules here so this test always starts from a consistent state,
        # then rebuild MOCK_TASK_CLASSES with fresh class definitions.
        from secator.utils_test import clear_modules
        clear_modules()
        self._rebuild_mock_tasks()

    def _rebuild_mock_tasks(self):
        """Recreate mock task classes using fresh secator imports.

        After clear_modules(), the module-level w1_1/w2_1/etc. classes have stale bases
        (PythonRunner from the old import). Celery's pickle fails because Target objects
        created via those stale classes don't match sys.modules classes.
        We rebuild fresh classes and update MOCK_TASK_CLASSES in-place.
        """
        from secator.runners import PythonRunner as _PythonRunner
        from secator.output_types import Port as _Port, Tag as _Tag, Url as _Url
        from secator.output_types import Technology as _Technology
        from secator.definitions import HOST as _HOST, HOST_PORT as _HOST_PORT, URL as _URL
        from secator.decorators import task as _task

        @_task()
        class _w1_1(_PythonRunner):
            input_types = [_HOST]
            output_types = [_Port]

            def yielder(self):
                MOCK_INPUTS['w1_1'] = sorted(self.inputs)
                for target in self.inputs:
                    yield _Port(ip=target, host=target, port=80, protocol='tcp')
                    yield _Port(ip=target, host=target, port=443, protocol='tcp')
                    yield _Port(ip=target, host=target, port=445, protocol='tcp')

        _w1_1.__name__ = 'w1_1'
        _w1_1.__qualname__ = 'w1_1'

        @_task()
        class _w1_2(_PythonRunner):
            input_types = [_URL]
            output_types = [_Technology]

            def yielder(self):
                MOCK_INPUTS['w1_2'] = sorted(self.inputs)
                for target in self.inputs:
                    yield _Technology(match=target, product='Apache', version='2.4')

        _w1_2.__name__ = 'w1_2'
        _w1_2.__qualname__ = 'w1_2'

        @_task()
        class _w2_1(_PythonRunner):
            input_types = [_HOST_PORT]
            output_types = [_Tag]

            def yielder(self):
                MOCK_INPUTS['w2_1'] = sorted(self.inputs)
                for target in self.inputs:
                    yield _Tag(name='smb', match=target, category='secret')

        _w2_1.__name__ = 'w2_1'
        _w2_1.__qualname__ = 'w2_1'

        @_task()
        class _w2_2(_PythonRunner):
            input_types = [_HOST_PORT]
            output_types = [_Url]

            def yielder(self):
                MOCK_INPUTS['w2_2'] = sorted(self.inputs)
                for target in self.inputs:
                    yield _Url(url=f'http://{target}', status_code=200)

        _w2_2.__name__ = 'w2_2'
        _w2_2.__qualname__ = 'w2_2'

        @_task()
        class _w2_3(_PythonRunner):
            input_types = [_HOST_PORT, _URL]
            output_types = [_Tag]

            def yielder(self):
                MOCK_INPUTS['w2_3'] = sorted(self.inputs)
                for target in self.inputs:
                    yield _Tag(name='found-secret', match=target, category='verified')

        _w2_3.__name__ = 'w2_3'
        _w2_3.__qualname__ = 'w2_3'

        # Update MOCK_TASK_CLASSES in-place so patched_discover_tasks returns fresh classes
        MOCK_TASK_CLASSES.clear()
        MOCK_TASK_CLASSES.extend([_w1_1, _w1_2, _w2_1, _w2_2, _w2_3])

    def _run_chain(self):
        """Build and apply the full scan Celery workflow."""
        from secator.runners import Scan, Workflow  # noqa: F401
        from secator.celery import mark_runner_started  # noqa: F401

        scan_config = make_scan_config()
        wf1_config = make_workflow1_config()
        wf2_config = make_workflow2_config()
        all_configs = [wf1_config, wf2_config, scan_config]

        scan_inputs = ['example.com', 'http://example.com']

        def mock_find_templates():
            return all_configs

        with patch('secator.loader.find_templates', side_effect=mock_find_templates), \
             patch('secator.runners.task.discover_tasks', side_effect=patched_discover_tasks):
            scan = Scan(scan_config, inputs=scan_inputs, run_opts={})
            sig = scan.build_celery_workflow()
            result = sig.apply()
            return result.get()

    def test_workflow1_w1_1_receives_host_targets(self):
        """w1_1 must receive only host-type targets from workflow1 inputs."""
        self._run_chain()
        self.assertIn('w1_1', MOCK_INPUTS, "w1_1 never ran")
        self.assertEqual(MOCK_INPUTS['w1_1'], ['example.com'])

    def test_workflow1_w1_2_receives_url_targets(self):
        """w1_2 must receive only URL-type targets from workflow1 inputs."""
        self._run_chain()
        self.assertIn('w1_2', MOCK_INPUTS, "w1_2 never ran")
        self.assertEqual(MOCK_INPUTS['w1_2'], ['http://example.com'])

    def test_workflow2_w2_1_receives_port_445_only(self):
        """w2_1 must receive only host:port targets containing '445'."""
        self._run_chain()
        self.assertIn('w2_1', MOCK_INPUTS, "w2_1 never ran")
        inputs = MOCK_INPUTS['w2_1']
        self.assertTrue(all('445' in t for t in inputs),
            f"w2_1 received non-445 targets: {inputs}")
        self.assertTrue(len(inputs) > 0, "w2_1 received no inputs (skipped)")

    def test_workflow2_w2_2_receives_all_port_targets(self):
        """w2_2 (no extractor) must receive ALL host:port targets resolved by workflow2."""
        self._run_chain()
        self.assertIn('w2_2', MOCK_INPUTS, "w2_2 never ran (THE BUG — this must now pass)")
        inputs = MOCK_INPUTS['w2_2']
        self.assertTrue(len(inputs) >= 3,
            f"w2_2 expected ≥3 port targets (80, 443, 445), got: {inputs}")

    def test_workflow2_w2_3_receives_tags_and_urls(self):
        """w2_3 must receive tag.match values (secret) + url.url values (status=200) from workflow2."""
        self._run_chain()
        self.assertIn('w2_3', MOCK_INPUTS, "w2_3 never ran")
        inputs = MOCK_INPUTS['w2_3']
        self.assertTrue(len(inputs) > 0, "w2_3 received no inputs")
        has_tag_input = any('445' in t for t in inputs)
        self.assertTrue(has_tag_input, f"w2_3 missing secret tag inputs: {inputs}")
