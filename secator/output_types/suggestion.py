import time
from dataclasses import dataclass, field

from secator.definitions import NAME, TYPE
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


@dataclass
class Suggestion(OutputType):
	"""A runner suggestion: a task, workflow or scan worth running next on some targets.

	Not a finding: drivers store it in their own suggestions store, never with findings.
	"""
	name: str
	type: str
	targets: list = field(default_factory=list)
	opts: dict = field(default_factory=dict, compare=False)
	reason: str = field(default='', compare=False)
	priority: str = field(default='medium', compare=False)  # low, medium, high
	source: str = field(default='', compare=False)  # who made it, e.g. ai
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='suggestion', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [TYPE, NAME, 'targets', 'priority', 'reason']
	_sort_by = ('_timestamp',)

	def __str__(self) -> str:
		return f'{self.type} {self.name}'

	def __rich__(self) -> str:
		s = rf'💡 [bold white]{_s(self.type)} {_s(self.name)}[/] \[[yellow]{_s(self.priority)}[/]]'
		if self.targets:
			s += f' on [cyan]{_s(", ".join(map(str, self.targets)))}[/]'
		if self.reason:
			s += f': [dim]{_s(self.reason)}[/]'
		return s

	def __repr__(self) -> str:
		return rich_to_ansi(self.__rich__())
