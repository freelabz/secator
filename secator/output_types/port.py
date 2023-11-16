import time
from dataclasses import dataclass, field

from secator.definitions import CPES, EXTRA_DATA, HOST, IP, PORT
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Port(OutputType):
	port: int
	ip: str
	state: str = 'UNKNOWN'
	service_name: str = field(default='', compare=False)
	cpes: list = field(default_factory=list, compare=False)
	host: str = field(default='', repr=True, compare=False)
	extra_data: dict = field(default_factory=dict, compare=False)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='port', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [IP, PORT, HOST, CPES, EXTRA_DATA]
	_sort_by = (PORT, IP)

	def __gt__(self, other):
		# favor nmap over other port detection tools
		if self._source == 'nmap' and other._source != 'nmap':
			return True
		return super().__gt__(other)

	def __str__(self) -> str:
		return f'{self.host}:{self.port}'

	def __repr__(self) -> str:
		s = f'🔓 {self.ip}:[bold red]{self.port:<4}[/] [bold yellow]{self.state.upper()}[/]'
		if self.service_name:
			s += f' \[[bold purple]{self.service_name}[/]]'
		if self.host:
			s += f' \[[cyan]{self.host}[/]]'
		return rich_to_ansi(s)
