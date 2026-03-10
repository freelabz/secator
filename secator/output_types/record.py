import time
from dataclasses import dataclass, field

from secator.definitions import HOST, NAME, TYPE
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object, rich_escape as _s


@dataclass
class Record(OutputType):
	name: str
	type: str
	host: str = ''
	extra_data: dict = field(default_factory=dict, compare=False)
	is_false_positive: bool = field(default=False, compare=False)
	is_acknowledged: bool = field(default=False, compare=False)
	tags: list = field(default_factory=list, compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='record', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [NAME, HOST, TYPE]
	_sort_by = (TYPE, NAME)

	def __str__(self) -> str:
		return self.name

	def __rich__(self) -> str:
		s = rf'🎤 [bold white]{_s(self.name)}[/] \[[green]{_s(self.type)}[/]]'
		if self.host:
			s += rf' \[[magenta]{_s(self.host)}[/]]'
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')
		return s

	def __repr__(self) -> str:
		return rich_to_ansi(self.__rich__())
