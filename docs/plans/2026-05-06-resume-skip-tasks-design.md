# Resume & Skip Tasks Design

## Overview

Add `--from` and `--skip` options to `secator w` and `secator s` commands, enabling users to resume a previous run by pre-populating results and skipping specific task nodes.

**Examples:**
```bash
secator w host_recon --from workflows/6 --skip nmap/light,nmap
secator s domain --from scans/6 --skip host_recon.nmap/light,host_recon.nmap
```

## Approach

CLI-layer resolution + graph-builder skip (Approach A):
- `--from` is resolved to prior results via `QueryEngine` before the runner is instantiated
- Prior results are passed via the existing `results=` parameter on `Runner.__init__`
- `--skip` is threaded through `run_opts` and consulted in the Celery graph builders
- No changes to `Runner` base class required

## CLI Interface

Two new entries in `CLI_EXEC_OPTS` in `secator/cli_helper.py`:

```python
'from': {
    'type': str,
    'default': None,
    'help': 'Load previous results from a run ID (e.g. workflows/6, scans/abc-uuid)',
    'short': 'f',
},
'skip': {
    'type': str,
    'default': None,
    'help': 'Comma-separated task node names to skip (e.g. nmap/light,nmap or host_recon.nmap for scans)',
    'short': 'sk',
},
```

In the `func` closure of `register_runner()`, before runner instantiation:

```python
from_ref = opts.pop('from', None)
skip_raw = opts.pop('skip', None)
skip = [s.strip() for s in skip_raw.split(',')] if skip_raw else []

prior_results = []
if from_ref:
    runner_type, run_id = from_ref.split('/', 1)
    query = {f'{runner_type[:-1]}_id': run_id}  # "workflows/6" → {'workflow_id': '6'}
    prior_results = QueryEngine(context=context).search(query)

runner = runner_cls(config, inputs, results=prior_results, run_opts={**opts, 'skip': skip}, ...)
```

The `QueryEngine` resolves the reference using the active backend (JSON filesystem, MongoDB, or API) based on the `--driver` option already present in `context`.

## Workflow Graph Builder Skip

In `Workflow.build_celery_workflow()`, inside the `process_task()` nested function, check the skip list before the existing `if`-condition logic:

```python
skip = self.run_opts.get('skip', [])
node_name = node.name  # matches YAML key exactly: "nmap/light", "nmap", "httpx"

if node_name in skip:
    self.add_result(Info(message=f'Task {node_name} skipped.'))
    return  # not added to Celery graph
```

Node names match YAML keys exactly (e.g. `nmap/light`, `nmap`).

## Scan Graph Builder Skip Routing

In `Scan.build_celery_workflow()`, before creating each child `Workflow` runner, strip the workflow prefix and forward the filtered skip list:

```python
skip = self.run_opts.get('skip', [])

for wf_name, wf_config in self.config.workflows.items():
    # "host_recon.nmap/light" → "nmap/light" for host_recon workflow
    # bare names (no ".") apply to all workflows
    wf_skip = [
        s.split('.', 1)[1] for s in skip
        if s.startswith(f'{wf_name}.')
    ] + [s for s in skip if '.' not in s]

    wf_runner = Workflow(wf_config, ..., run_opts={**run_opts, 'skip': wf_skip})
```

## Data Flow

### Workflow resume

`secator w host_recon --from workflows/6 --skip nmap/light,nmap`:

1. CLI resolves `workflows/6` → `QueryEngine(context).search({'workflow_id': '6'})` → list of `OutputType` dicts
2. Runner instantiated with `results=prior_results`, `run_opts={'skip': ['nmap/light', 'nmap']}`
3. Runner `__init__` pre-populates `self.results` (existing logic, unchanged)
4. Graph builder skips `nmap/light` and `nmap` nodes with `Info` messages
5. Remaining tasks (`sshaudit`, `httpx`, etc.) derive inputs from pre-populated results via `targets_` selectors

### Scan resume

`secator s domain --from scans/6 --skip host_recon.nmap/light,host_recon.nmap`:

Same as above, but at scan level: prefix `host_recon.` is stripped before forwarding `['nmap/light', 'nmap']` to the `host_recon` child workflow runner.

## Files to Change

| File | Change |
|------|--------|
| `secator/cli_helper.py` | Add `from` and `skip` to `CLI_EXEC_OPTS`; resolve `--from` and parse `--skip` in `register_runner()` func closure |
| `secator/runners/workflow.py` | Check skip list in `process_task()` before adding node to Celery graph |
| `secator/runners/scan.py` | Parse and route scoped skip entries to child workflow runners |

## Non-Goals

- No mutations to the YAML config on disk
- No changes to `Runner` base class
- No new persistence layer — uses existing `QueryEngine` and `results=` parameter
