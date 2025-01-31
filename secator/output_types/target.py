import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


@dataclass
class Target(OutputType):
	name: str
	_source: str = field(default='', repr=True)
	_type: str = field(default='target', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [
		'name',
	]
	_sort_by = ('name',)

	def __str__(self):
		return self.name

	def __repr__(self):
		s = f'🎯 {_s(self.name)}'
		return rich_to_ansi(s)
