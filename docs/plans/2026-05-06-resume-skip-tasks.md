# Resume & Skip Tasks Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `--from` and `--skip` CLI options to `secator w` and `secator s` so users can resume a previous run by pre-populating results and skipping specific task nodes.

**Architecture:** `--from <runner_type/run_id>` is resolved to prior results via `QueryEngine` (using the active driver's backend) before the runner is instantiated, then passed via the existing `results=` parameter. `--skip <comma-separated node names>` is parsed into a list, stored in `run_opts['skip']`, and consumed by the Workflow graph builder before adding each node to the Celery chain. Scan-level skip entries are prefixed `workflow_name.task_name` and routed to the correct child Workflow runner.

**Tech Stack:** Python, Click, Celery, secator QueryEngine (`secator/query/`), TemplateLoader, PythonRunner

---

### Task 1: Add `--from` and `--skip` to CLI_EXEC_OPTS

**Files:**
- Modify: `secator/cli_helper.py:54` (after the `enable_memray` entry, before the closing `}`)

**Step 1: Add the two new entries**

In `secator/cli_helper.py`, find the end of `CLI_EXEC_OPTS` (currently ends at line 55 with `}`). Add after the `enable_memray` line (line 54):

```python
	'from': {'type': str, 'default': None, 'short': 'f', 'help': 'Load previous results from a run (e.g. workflows/6, scans/abc-uuid)'},
	'skip': {'type': str, 'default': None, 'short': 'sk', 'help': 'Comma-separated task node names to skip (e.g. nmap/light,nmap or host_recon.nmap for scans)'},
```

**Step 2: Verify with lint**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test lint
```

Expected: no new errors.

**Step 3: Commit**

```bash
git add secator/cli_helper.py
git commit -m "feat(cli): add --from and --skip options to CLI_EXEC_OPTS"
```

---

### Task 2: Resolve `--from` and parse `--skip` in the func closure

**Files:**
- Modify: `secator/cli_helper.py` — inside `func` (around line 317, after `deep_merge_dicts`)
- Modify: `secator/cli_helper.py:367-368` — runner instantiation

**Context:** `func` starts at line 218. The driver/context setup completes around line 317 (`hooks = deep_merge_dicts(*hooks)`). Place the resolution block right after that line so `context['drivers']` is already populated (needed for QueryEngine backend selection).

**Step 1: Add resolution block after `hooks = deep_merge_dicts(*hooks)` (line 317)**

```python
		# Resolve --from and --skip
		from_ref = opts.pop('from', None)
		skip_raw = opts.pop('skip', None)
		opts['skip'] = [s.strip() for s in skip_raw.split(',')] if skip_raw else []

		prior_results = []
		if from_ref:
			from secator.query import QueryEngine
			from secator.query.utils import parse_report_paths
			query = parse_report_paths(from_ref)
			prior_results = QueryEngine(ws, context=context).search(query)
```

**Step 2: Pass `results=prior_results` to runner instantiation (line 367)**

Change:
```python
			runner = runner_cls(
				config, inputs, run_opts=opts, hooks=hooks, context=context
			)
```
To:
```python
			runner = runner_cls(
				config, inputs, results=prior_results, run_opts=opts, hooks=hooks, context=context
			)
```

**Step 3: Verify with lint**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test lint
```

Expected: no new errors.

**Step 4: Commit**

```bash
git add secator/cli_helper.py
git commit -m "feat(cli): resolve --from via QueryEngine and pass skip list to runner"
```

---

### Task 3: Workflow skip logic (TDD)

**Files:**
- Create: `tests/unit/test_skip_tasks.py`
- Modify: `secator/runners/workflow.py:28-33` (pop skip from opts)
- Modify: `secator/runners/workflow.py:76-91` (add skip check before if-condition)

#### Step 1: Write the failing test

Create `tests/unit/test_skip_tasks.py`:

```python
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
```

**Step 2: Run the test to verify it fails**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test unit --test test_skip_tasks
```

Expected: FAIL — `fake_a` still appears in the graph because skip logic doesn't exist yet.

**Step 3: Implement skip in `secator/runners/workflow.py`**

**3a.** In `build_celery_workflow()`, after the existing `opts.pop(...)` calls (around line 29-32), add:

```python
		skip = opts.pop('skip', [])
```

This pops the skip list from opts so it is not forwarded to individual task opts, and makes it available to the `process_task` closure.

**3b.** In `process_task()`, add the skip check immediately after the `if node.type == 'task':` guard (before the existing `if` condition check at line 81):

```python
				# Skip task if in skip list
				if node.name in skip:
					self.add_result(Info(message=f'Skipped task [bold gold3]{node.name}[/] because it is in the skip list.'))
					return
```

The complete `process_task` function start (lines 76-91) should look like:

```python
			if node.type == 'task':
				if node.parent.type == 'group' and not force:
					return

				# Skip task if in skip list
				if node.name in skip:
					self.add_result(Info(message=f'Skipped task [bold gold3]{node.name}[/] because it is in the skip list.'))
					return

				# Skip task if condition is not met
				condition = node.opts.pop('if', None)
				...
```

**Step 4: Run the test to verify it passes**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test unit --test test_skip_tasks
```

Expected: PASS for all three tests.

**Step 5: Run full unit test suite to check for regressions**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test unit
```

Expected: all existing tests still pass.

**Step 6: Commit**

```bash
git add tests/unit/test_skip_tasks.py secator/runners/workflow.py
git commit -m "feat(workflow): skip task nodes present in run_opts['skip']"
```

---

### Task 4: Scan skip routing (TDD)

**Files:**
- Modify: `tests/unit/test_skip_tasks.py` — add scan routing tests
- Modify: `secator/runners/scan.py:39-47` — compute per-workflow skip before `merge_opts`

#### Step 1: Add failing scan tests to `tests/unit/test_skip_tasks.py`

Add to the file (after `TestWorkflowSkip`):

```python
class TestScanSkipRouting(unittest.TestCase):
    """Verify that scan-level skip entries are routed to the correct child workflow."""

    def _compute_wf_skip(self, skip, wf_name):
        """Helper: replicate the routing logic from scan.build_celery_workflow()."""
        bare = [s for s in skip if '.' not in s]
        scoped = [s.split('.', 1)[1] for s in skip if s.startswith(f'{wf_name}.')]
        return bare + scoped

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
```

**Step 2: Run to verify tests pass (routing logic is pure, no scan runner needed)**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test unit --test test_skip_tasks
```

Expected: `TestScanSkipRouting` tests PASS immediately (they test the pure routing formula, independent of the runner).

**Step 3: Implement routing in `secator/runners/scan.py`**

In `build_celery_workflow()`, add the skip routing block **after** `run_opts['reports_folder'] = ...` (line 46) and **before** `opts = merge_opts(...)` (line 47):

```python
			# Route skip entries to this workflow
			skip = self.run_opts.get('skip', [])
			wf_name = name.split('/')[0]
			wf_skip = [s.split('.', 1)[1] for s in skip if s.startswith(f'{wf_name}.')] \
					  + [s for s in skip if '.' not in s]
			run_opts['skip'] = wf_skip
```

The updated block (lines 39-48 area) should look like:

```python
			run_opts = self.run_opts.copy()
			run_opts.pop('profiles', None)
			run_opts['no_poll'] = True
			run_opts['caller'] = 'Scan'
			run_opts['has_parent'] = True
			run_opts['enable_reports'] = False
			run_opts['print_profiles'] = False
			run_opts['reports_folder'] = str(self.reports_folder)
			# Route skip entries to this workflow
			skip = self.run_opts.get('skip', [])
			wf_name = name.split('/')[0]
			wf_skip = [s.split('.', 1)[1] for s in skip if s.startswith(f'{wf_name}.')] \
					  + [s for s in skip if '.' not in s]
			run_opts['skip'] = wf_skip
			opts = merge_opts(scan_opts, workflow_opts, run_opts)
			name = name.split('/')[0]
```

**Step 4: Run full unit test suite**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test unit
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add tests/unit/test_skip_tasks.py secator/runners/scan.py
git commit -m "feat(scan): route scoped skip entries to child workflow runners"
```

---

### Task 5: Final verification

**Step 1: Run lint**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test lint
```

Expected: clean.

**Step 2: Run full unit tests**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate && secator test unit
```

Expected: all pass.

**Step 3: Manual smoke test — skip only (no --from)**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
secator w host_recon --dry-run --skip nmap/light,nmap --help
```

Expected: `--skip` and `--from` appear in help output with their descriptions.

**Step 4: Commit any final fixes, then mark branch ready for review**

```bash
git log --oneline -5
```
