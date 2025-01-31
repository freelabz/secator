import time
from dataclasses import dataclass, field

from secator.definitions import HOST, NAME, TYPE
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


@dataclass
class Record(OutputType):
	name: str
	type: str
	host: str = ''
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True)
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

	def __repr__(self) -> str:
		s = rf'🎤 [bold white]{self.name}[/] \[[green]{self.type}[/]]'
		if self.host:
			s += rf' \[[magenta]{self.host}[/]]'
		if self.extra_data:
			s += r' \[[bold yellow]' + ','.join(f'{_s(k)}={_s(v)}' for k, v in self.extra_data.items()) + '[/]]'
		return rich_to_ansi(s)
