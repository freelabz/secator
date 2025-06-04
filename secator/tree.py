from typing import List, Optional, Union
from secator.template import TemplateLoader
from dotmap import DotMap


DEFAULT_RENDER_OPTS = {
	'group': lambda x: f"[dim]group {x.name.split('/')[-1] if '/' in x.name else ''}[/]",
	'task': lambda x: f"[bold gold3]:wrench: {x.name}[/]",
	'workflow': lambda x: f"[bold dark_orange3]:gear: {x.name}[/]",
	'scan': lambda x: f"[bold red]:magnifying_glass_tilted_left: {x.name}[/]",
	'condition': lambda x: f"[dim cyan]# if {x}[/]" if x else ''
}


class TaskNode:
	"""Represents a node in the workflow/scan task tree."""
	def __init__(self, name: str, type_: str, id: str, opts: Optional[dict] = None, default_opts: Optional[dict] = None, condition: Optional[str] = None, description: Optional[str] = None, parent=None, ancestor=None):  # noqa: E501
		self.name = name
		self.type = type_
		self.id = id
		self.opts = opts or {}
		self.default_opts = default_opts or {}
		self.description = description
		self.condition = condition
		self.children: List[TaskNode] = []
		self.parent = parent
		self.ancestor = ancestor

	def add_child(self, child: 'TaskNode') -> None:
		"""Add a child node to this node."""
		self.children.append(child)

	def remove(self):
		"""Remove this node from its parent."""
		if self.parent:
			self.parent.children.remove(self)

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
			if child.description:
				render_str += f" - [dim]{child.description}[/]"
			if condition_str:
				render_str += f" {condition_str}"
			lines.append(render_str)
			if child.children:
				new_prefix = prefix + ("   " if is_last else "│  ")
				self._render_children(child, new_prefix, lines)

	def get_subtree(self, node: TaskNode) -> 'RunnerTree':
		"""Get the subtree of this node."""
		subtree = RunnerTree(node.name, node.type)
		for child in node.children:
			subtree.add_root_node(child)
		return subtree


def build_runner_tree(config: DotMap, condition: Optional[str] = None, parent: Optional[TaskNode] = None, ancestor: Optional[TaskNode] = None) -> Union[RunnerTree, str]:  # noqa: E501
	"""
	Build a tree representation from a runner config.

	Args:
		config (DotMap): The runner config.

	Returns:
		A RunnerTree object or an error message string
	"""
	tree = RunnerTree(config.name, config.type)

	if config.type == 'workflow':
		root_node = TaskNode(config.name, 'workflow', config.name, opts=config.options, default_opts=config.default_options, condition=condition, parent=parent, ancestor=ancestor)  # noqa: E501
		tree.add_root_node(root_node)

		# Add tasks to the tree
		for task_name, task_details in config.tasks.items():
			id = f'{config.name}.{task_name}'
			if task_name.startswith('_group'):
				group_node = TaskNode(task_name, 'group', id, parent=root_node, ancestor=root_node)
				root_node.add_child(group_node)
				for subtask_name, subtask_details in task_details.items():
					subtask_details = subtask_details or {}
					id = f'{config.name}.{subtask_name}'
					condition = subtask_details.get('if')
					description = subtask_details.get('description')
					subtask_node = TaskNode(subtask_name, 'task', id, opts=subtask_details, condition=condition, description=description, parent=group_node, ancestor=root_node)  # noqa: E501
					group_node.add_child(subtask_node)
			else:
				condition = task_details.get('if') if task_details else None
				description = task_details.get('description') if task_details else None
				task_node = TaskNode(task_name, 'task', id, opts=task_details, condition=condition, description=description, parent=root_node, ancestor=root_node)  # noqa: E501
				root_node.add_child(task_node)

	elif config.type == 'scan':
		id = f'{config.name}'
		root_node = TaskNode(config.name, 'scan', id, opts=config.options, parent=parent)
		tree.add_root_node(root_node)

		# Add workflows to the tree
		for workflow_name, workflow_details in config.workflows.items():
			id = f'{config.name}.{workflow_name}'
			condition = workflow_details.get('if') if isinstance(workflow_details, dict) else None
			split_name = workflow_name.split('/')
			wf_name = split_name[0]
			wf_config = TemplateLoader(name=f'workflow/{wf_name}')
			wf_config.name = workflow_name
			wf_tree = build_runner_tree(wf_config, condition, parent=root_node, ancestor=root_node)
			if isinstance(wf_tree, RunnerTree):
				for wf_root_node in wf_tree.root_nodes:
					root_node.add_child(wf_root_node)

	elif config.type == 'task':
		root_node = TaskNode(config.name, 'task', config.name, opts={}, parent=parent, ancestor=ancestor)
		tree.add_root_node(root_node)

	return tree


def walk_runner_tree(tree: RunnerTree, visit_func):
	"""
	Walk the RunnerTree and visit each node.

	Args:
		tree (RunnerTree): The RunnerTree to walk.
		visit_func (function): A function to call on each node.
	"""
	for root_node in tree.root_nodes:
		_walk_node(root_node, visit_func)


def _walk_node(node: TaskNode, visit_func):
	"""
	Recursively walk the node and its children.

	Args:
		node (TaskNode): The node to walk.
		visit_func (function): A function to call on each node.
	"""
	visit_func(node)
	for child in node.children:
		_walk_node(child, visit_func)


def get_flat_node_list(tree: RunnerTree) -> List[TaskNode]:
	"""
	Get the flat list of all nodes in the RunnerTree.

	Args:
		tree (RunnerTree): The RunnerTree to traverse.

	Returns:
		List[TaskNode]: The list of all nodes in the tree.
	"""
	nodes = []

	def collect_node(node: TaskNode):
		nodes.append(node)

	walk_runner_tree(tree, collect_node)
	return nodes
