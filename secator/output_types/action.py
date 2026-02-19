import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


@dataclass
class Action(OutputType):
	"""Represents an AI-generated action for attack mode."""
	action: str  # execute, validate, complete, stop
	action_type: str = field(default='')  # task, workflow, scan, shell (for execute)
	name: str = field(default='')  # runner name or command
	targets: list = field(default_factory=list)
	opts: dict = field(default_factory=dict)
	reasoning: str = field(default='')
	expected_outcome: str = field(default='')
	# For validate action
	vulnerability: str = field(default='')
	proof: str = field(default='')
	severity: str = field(default='')
	reproduction_steps: list = field(default_factory=list)
	# For complete action
	summary: str = field(default='')
	# For stop action
	reason: str = field(default='')
	# Standard fields
	extra_data: dict = field(default_factory=dict, repr=True, compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='action', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['action', 'action_type', 'name', 'targets', 'reasoning']
	_sort_by = ('_timestamp',)

	def __repr__(self):
		if self.action == 'execute':
			return self._repr_execute()
		elif self.action == 'validate':
			return self._repr_validate()
		elif self.action == 'complete':
			return self._repr_complete()
		elif self.action == 'stop':
			return self._repr_stop()
		else:
			return self._repr_unknown()

	def _repr_execute(self):
		"""Render execute action."""
		icon = self._get_type_icon()
		type_color = self._get_type_color()

		# Build command preview
		if self.action_type == 'shell':
			cmd = _s(self.name)
			s = rf'{icon} \[[bold {type_color}]SHELL[/]] [bold white]{cmd}[/]'
		else:
			targets_str = ', '.join(self.targets[:3])
			if len(self.targets) > 3:
				targets_str += f' (+{len(self.targets) - 3})'
			s = rf'{icon} \[[bold {type_color}]{self.action_type.upper()}[/]] [bold white]{self.name}[/] [dim]→[/] [cyan]{targets_str}[/]'

		# Add opts if present
		if self.opts:
			opts_str = ', '.join(f'{k}={v}' for k, v in list(self.opts.items())[:3])
			if len(self.opts) > 3:
				opts_str += ' ...'
			s += f'\n    [dim]opts:[/] [yellow]{opts_str}[/]'

		# Add reasoning
		if self.reasoning:
			reasoning = _s(self.reasoning[:200])
			if len(self.reasoning) > 200:
				reasoning += '...'
			s += f'\n    [dim]reason:[/] [italic]{reasoning}[/]'

		return rich_to_ansi(s)

	def _repr_validate(self):
		"""Render validate action."""
		severity_colors = {
			'critical': 'red bold',
			'high': 'red',
			'medium': 'yellow',
			'low': 'blue',
			'info': 'dim',
		}
		sev_color = severity_colors.get(self.severity.lower(), 'white')
		s = rf'[bold green]VALIDATED[/] \[[{sev_color}]{self.severity.upper()}[/]] [bold white]{_s(self.vulnerability)}[/]'
		if self.targets:
			s += f' @ [cyan]{_s(self.targets[0] if isinstance(self.targets, list) else self.targets)}[/]'
		if self.proof:
			proof = _s(self.proof[:150])
			if len(self.proof) > 150:
				proof += '...'
			s += f'\n    [dim]proof:[/] [yellow]{proof}[/]'
		return rich_to_ansi(s)

	def _repr_complete(self):
		"""Render complete action."""
		s = rf'[bold green]COMPLETE[/]'
		if self.summary:
			summary = _s(self.summary[:300])
			if len(self.summary) > 300:
				summary += '...'
			s += f' [dim]{summary}[/]'
		return rich_to_ansi(s)

	def _repr_stop(self):
		"""Render stop action."""
		s = rf'[bold yellow]STOPPED[/]'
		if self.reason:
			reason = _s(self.reason[:200])
			if len(self.reason) > 200:
				reason += '...'
			s += f' [dim]{reason}[/]'
		return rich_to_ansi(s)

	def _repr_unknown(self):
		"""Render unknown action."""
		s = rf'[bold magenta]ACTION[/] [white]{self.action}[/]'
		return rich_to_ansi(s)

	def _get_type_icon(self):
		"""Get icon for action type."""
		icons = {
			'task': '',
			'workflow': '',
			'scan': '',
			'shell': '',
		}
		return icons.get(self.action_type, '')

	def _get_type_color(self):
		"""Get color for action type."""
		colors = {
			'task': 'cyan',
			'workflow': 'magenta',
			'scan': 'green',
			'shell': 'yellow',
		}
		return colors.get(self.action_type, 'white')

	@classmethod
	def from_dict(cls, data: dict) -> 'Action':
		"""Create an Action from a parsed JSON dict."""
		action_type = data.get('action', '')

		# Handle targets - can be list or single target field
		targets = data.get('targets', [])
		if not targets and data.get('target'):
			targets = [data.get('target')]

		# For shell commands, name is the command
		name = data.get('name', '')
		if not name and data.get('command'):
			name = data.get('command', '')

		return cls(
			action=action_type,
			action_type=data.get('type', ''),
			name=name,
			targets=targets,
			opts=data.get('opts', {}),
			reasoning=data.get('reasoning', ''),
			expected_outcome=data.get('expected_outcome', ''),
			vulnerability=data.get('vulnerability', ''),
			proof=data.get('proof', ''),
			severity=data.get('severity', ''),
			reproduction_steps=data.get('reproduction_steps', []),
			summary=data.get('summary', ''),
			reason=data.get('reason', ''),
		)
