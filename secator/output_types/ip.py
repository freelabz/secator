import time
from dataclasses import dataclass, field

from secator.definitions import ALIVE, IP
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Ip(OutputType):
	ip: str
	host: str = ''
	alive: bool = False
	_source: str = field(default='', repr=True)
	_type: str = field(default='ip', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [IP, ALIVE]
	_sort_by = (IP,)

	def __str__(self) -> str:
		return self.ip

	def __repr__(self) -> str:
		s = f'💻 [bold white]{self.ip}[/]'
		if self.host:
			s += f' \[[bold magenta]{self.host}[/]]'
		return rich_to_ansi(s)
