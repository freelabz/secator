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
