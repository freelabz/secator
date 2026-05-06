# Design: Pruned Scan/Workflow Tree Display

## Problem

When a scan or workflow is built, the "Scan built:" / "Workflow built:" info message shows the full tree including nodes that will be skipped because their `if` conditions evaluate to `False` against the current opts/targets. The displayed tree should reflect only what will actually run.

## Scope

- Only prune nodes whose `if` conditions evaluate to `False` against the current `opts` and `targets` at start time.
- Do not attempt to prune nodes that may be skipped dynamically at runtime (e.g., tasks skipped due to no inputs from a previous step).

## Chosen Approach: Prune after build

Build the full tree as today, then walk it and remove condition-failing nodes before rendering. This leaves `build_runner_tree()` unchanged (the execution path in `workflow.py` and `scan.py` calls it separately and is unaffected).

## Changes

### 1. `secator/tree.py` — add `prune_runner_tree()`

```python
def prune_runner_tree(tree: RunnerTree, opts: dict, inputs: list = None) -> RunnerTree:
    from dotmap import DotMap
    safe_globals = {'__builtins__': {'len': len}}
    local_ns = {'opts': DotMap(opts), 'targets': inputs or []}

    def prune_node(node: TaskNode):
        for child in list(node.children):
            prune_node(child)
        if node.condition:
            try:
                if not eval(node.condition, safe_globals, local_ns):
                    node.remove()
            except Exception:
                pass  # keep node on eval error

    for root in tree.root_nodes:
        prune_node(root)

    return tree
```

Key decisions:
- Bottom-up traversal so child removals don't corrupt parent iteration.
- On eval error, node is kept (err on the side of showing more).
- Mutates in-place (safe — `build_runner_tree()` produces a fresh tree each call).

### 2. `secator/runners/_base.py` — update `log_start()`

```python
# Before
tree = textwrap.indent(build_runner_tree(self.config).render_tree(), '      ')

# After
tree = build_runner_tree(self.config)
prune_runner_tree(tree, self.run_opts, self.inputs)
tree = textwrap.indent(tree.render_tree(), '      ')
```

Add `prune_runner_tree` to the import from `secator.tree`.

## Files Touched

| File | Change |
|------|--------|
| `secator/tree.py` | Add `prune_runner_tree()` function |
| `secator/runners/_base.py` | Import and call `prune_runner_tree()` in `log_start()` |

## Not Changed

- `secator/runners/workflow.py` — execution-time condition evaluation unchanged
- `secator/runners/scan.py` — execution-time condition evaluation unchanged
- `build_runner_tree()` signature — unchanged
