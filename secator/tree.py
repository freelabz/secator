from typing import List, Optional, Union
from secator.template import TemplateLoader

DEFAULT_RENDER_OPTS = {
    'group': lambda x: f"[dim]{x.name}[/]",
    'task': lambda x: f"[bold gold3]:wrench: {x.name}[/]",
    'workflow': lambda x: f"[bold orange3]:gear: {x.name}[/]",
    'scan': lambda x: f"[bold green3]:magnifying_glass_tilted_left: {x.name}[/]",
    'condition': lambda x: f"[dim blue]# if {x}[/]" if x else ''
}


class TaskNode:
    """Represents a node in the workflow/scan task tree."""
    def __init__(self, name: str, type_: str, condition: Optional[str] = None):
        self.name = name
        self.type = type_
        self.condition = condition
        self.children: List[TaskNode] = []

    def add_child(self, child: 'TaskNode') -> None:
        """Add a child node to this node."""
        self.children.append(child)

    def __str__(self) -> str:
        """String representation with condition if present."""
        if self.condition:
            return f"{self.name} # if {self.condition}"
        return self.name


class RunnerTree:
    """Represents a tree of workflow/scan tasks."""
    def __init__(self, name: str, type_: str, render_opts: Optional[dict] = DEFAULT_RENDER_OPTS):
        self.name = name
        self.type = type_
        self.root_nodes: List[TaskNode] = []
        self.render_opts = render_opts

    def add_root_node(self, node: TaskNode) -> None:
        """Add a root-level node to the tree."""
        self.root_nodes.append(node)

    def render_tree(self) -> str:
        """Render the tree as a console-friendly string."""
        lines = []
        for node in self.root_nodes:
            node_str = self.render_opts.get(node.type, lambda x: str(x))(node)
            condition_str = self.render_opts.get('condition', lambda x: str(x) if x else '')(node.condition)
            if condition_str:
                node_str = f"{node_str} {condition_str}"
            lines.append(node_str)
            self._render_children(node, "", lines)
        return "\n".join(lines)

    def _render_children(self, node: TaskNode, prefix: str, lines: List[str]) -> None:
        """Helper method to recursively render child nodes."""
        children_count = len(node.children)
        for i, child in enumerate(node.children):
            is_last = i == children_count - 1
            branch = "└─ " if is_last else "├─ "
            child_str = self.render_opts.get(child.type, lambda x: str(x))
            condition_str = self.render_opts.get('condition', lambda x: str(x) if x else '')(child.condition)
            render_str = f"{prefix}{branch}{child_str(child)}"
            if condition_str:
                render_str = f"{render_str} {condition_str}"
            lines.append(render_str)
            if child.children:
                new_prefix = prefix + ("   " if is_last else "│  ")
                self._render_children(child, new_prefix, lines)


def build_runner_tree(config: TemplateLoader, condition: Optional[str] = None) -> Union[RunnerTree, str]:
    """
    Build a tree representation from a runner config.

    Args:
        config (TemplateLoader): The runner config.

    Returns:
        A RunnerTree object or an error message string
    """
    tree = RunnerTree(config.name, config.type)

    if config.type == 'workflow':
        root_node = TaskNode(config.name, 'workflow', condition)
        tree.add_root_node(root_node)

        # Add tasks to the tree
        for task_name, task_details in config.tasks.items():
            if task_name.startswith('_group'):
                group_node = TaskNode(task_name, 'group')
                root_node.add_child(group_node)
                for subtask_name, subtask_details in task_details.items():
                    condition = subtask_details.get('if')
                    subtask_node = TaskNode(subtask_name, 'task', condition)
                    group_node.add_child(subtask_node)
            else:
                condition = task_details.get('if')
                task_node = TaskNode(task_name, 'task', condition)
                root_node.add_child(task_node)

    elif config.type == 'scan':
        root_node = TaskNode(config.name, 'scan')
        tree.add_root_node(root_node)

        # Add workflows to the tree
        for workflow_name, workflow_details in config.workflows.items():
            condition = workflow_details.get('if') if isinstance(workflow_details, dict) else None
            wf_config = TemplateLoader(name=f'workflow/{workflow_name}')
            wf_tree = build_runner_tree(wf_config, condition)
            if isinstance(wf_tree, RunnerTree):
                for wf_root_node in wf_tree.root_nodes:
                    root_node.add_child(wf_root_node)
    return tree
