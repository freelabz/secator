# Pruned Scan/Workflow Tree Display Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Filter the "Scan built:" / "Workflow built:" tree so it only shows tasks/workflows whose `if` conditions evaluate to `True` against the current opts and targets.

**Architecture:** Add `prune_runner_tree(tree, opts, inputs)` to `secator/tree.py` that walks the built tree bottom-up, evaluates each node's condition string, and removes failing nodes. Call it from `log_start()` in `_base.py` between building and rendering the tree. Execution paths in `workflow.py` and `scan.py` are untouched.

**Tech Stack:** Python, dotmap (`DotMap`), stdlib `eval()` with restricted safe globals.

---

### Task 1: Add `prune_runner_tree()` with tests

**Files:**
- Modify: `secator/tree.py` (add function after `build_runner_tree`, around line 152)
- Create: `tests/unit/test_tree.py`

**Step 1: Write the failing tests**

Create `tests/unit/test_tree.py`:

```python
import unittest
from dotmap import DotMap
from secator.tree import TaskNode, RunnerTree, prune_runner_tree


def make_tree(*nodes):
    """Helper: build a RunnerTree with given root TaskNodes."""
    tree = RunnerTree('test', 'workflow')
    for node in nodes:
        tree.add_root_node(node)
    return tree


def make_node(name, condition=None, children=None):
    node = TaskNode(name, 'task', name, condition=condition)
    for child in (children or []):
        child.parent = node
        node.add_child(child)
    return node


class TestPruneRunnerTree(unittest.TestCase):

    def test_no_conditions_unchanged(self):
        """Nodes without conditions are never removed."""
        tree = make_tree(make_node('nmap'), make_node('httpx'))
        prune_runner_tree(tree, {})
        names = [n.name for n in tree.root_nodes]
        self.assertEqual(names, ['nmap', 'httpx'])

    def test_false_condition_removes_node(self):
        """Node with a False condition is removed from the tree."""
        tree = make_tree(
            make_node('nmap'),
            make_node('httpx', condition='opts.run_httpx'),
        )
        prune_runner_tree(tree, {'run_httpx': False})
        names = [n.name for n in tree.root_nodes]
        self.assertEqual(names, ['nmap'])

    def test_true_condition_keeps_node(self):
        """Node with a True condition is kept."""
        tree = make_tree(
            make_node('nmap', condition='opts.run_nmap'),
        )
        prune_runner_tree(tree, {'run_nmap': True})
        self.assertEqual(len(tree.root_nodes), 1)

    def test_bad_condition_keeps_node(self):
        """On eval error the node is kept (err on the side of showing more)."""
        tree = make_tree(make_node('nmap', condition='this is not valid python!!!'))
        prune_runner_tree(tree, {})
        self.assertEqual(len(tree.root_nodes), 1)

    def test_child_false_condition_removes_only_child(self):
        """A child with a false condition is removed; parent stays."""
        child = make_node('httpx', condition='opts.run_httpx')
        parent = make_node('discovery')
        parent.add_child(child)
        child.parent = parent
        tree = make_tree(parent)
        prune_runner_tree(tree, {'run_httpx': False})
        self.assertEqual(len(tree.root_nodes), 1)
        self.assertEqual(tree.root_nodes[0].children, [])

    def test_targets_available_in_condition(self):
        """Conditions can reference `targets`."""
        tree = make_tree(make_node('nmap', condition='len(targets) > 0'))
        prune_runner_tree(tree, {}, inputs=['192.168.1.1'])
        self.assertEqual(len(tree.root_nodes), 1)

    def test_targets_empty_removes_node(self):
        tree = make_tree(make_node('nmap', condition='len(targets) > 0'))
        prune_runner_tree(tree, {}, inputs=[])
        self.assertEqual(len(tree.root_nodes), 0)
```

**Step 2: Run tests to verify they fail**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
secator test unit --test test_tree
```

Expected: errors like `ImportError: cannot import name 'prune_runner_tree'`

**Step 3: Implement `prune_runner_tree()` in `secator/tree.py`**

Add after the `build_runner_tree` function (after line 152):

```python
def prune_runner_tree(tree: RunnerTree, opts: dict, inputs: list = None) -> RunnerTree:
    """Remove nodes whose conditions evaluate to False against opts/inputs.

    Walks bottom-up so child removals don't corrupt parent iteration.
    On eval error the node is kept (err on the side of showing more).
    """
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
                pass

    for root in list(tree.root_nodes):
        prune_node(root)
        # Also prune root nodes themselves if they carry a condition
        if root.condition:
            try:
                if not eval(root.condition, safe_globals, local_ns):
                    tree.root_nodes.remove(root)
            except Exception:
                pass

    return tree
```

**Step 4: Run tests to verify they pass**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
secator test unit --test test_tree
```

Expected: all 7 tests pass.

**Step 5: Lint check**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
secator test lint
```

Expected: no new errors (max-line-length=120).

**Step 6: Commit**

```bash
git add secator/tree.py tests/unit/test_tree.py
git commit -m "feat(tree): add prune_runner_tree to filter condition-failing nodes"
```

---

### Task 2: Wire `prune_runner_tree()` into `log_start()`

**Files:**
- Modify: `secator/runners/_base.py:23` (import line) and `:1021` (log_start body)

**Step 1: Update the import**

In `secator/runners/_base.py` line 23, change:

```python
from secator.tree import build_runner_tree
```

to:

```python
from secator.tree import build_runner_tree, prune_runner_tree
```

**Step 2: Update `log_start()` body**

In `secator/runners/_base.py` line 1021, change:

```python
tree = textwrap.indent(build_runner_tree(self.config).render_tree(), '      ')
```

to:

```python
tree = build_runner_tree(self.config)
prune_runner_tree(tree, self.run_opts, self.inputs)
tree = textwrap.indent(tree.render_tree(), '      ')
```

**Step 3: Run unit tests to check nothing regressed**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
secator test unit
```

Expected: all existing tests pass (no regressions).

**Step 4: Lint check**

```bash
source /home/jahmyst/Workspace/secator/.venv/bin/activate
secator test lint
```

Expected: no errors.

**Step 5: Commit**

```bash
git add secator/runners/_base.py
git commit -m "feat(runners): prune condition-failing nodes from start tree display"
```
