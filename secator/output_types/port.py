import time
from typing import Dict, List
from pydantic import Field

from secator.definitions import CPES, EXTRA_DATA, HOST, IP, PORT
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


class Port(OutputType):
	port: int
	ip: str
	state: str = 'UNKNOWN'
	service_name: str = ''
	cpes: List = Field(default_factory=list)
	host: str = ''
	protocol: str = 'tcp'
	extra_data: Dict = Field(default_factory=dict)
	confidence: str = 'low'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_source: str = ''
	_type: str = 'port'
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

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
		if self.protocol != 'TCP':
			s += rf' \[[yellow3]{self.protocol}[/]]'
		if self.service_name:
			conf = ''
			if self.confidence == 'low':
				conf = '[bold orange3]?[/]'
			s += rf' \[[bold purple]{self.service_name}{conf}[/]]'
		if self.host and self.host != self.ip:
			s += rf' \[[cyan]{self.host}[/]]'
		if self.extra_data:
			skip_keys = ['name', 'servicefp', 'method', 'service_name', 'product', 'version', 'conf']
			s += format_object(self.extra_data, 'yellow', skip_keys=skip_keys)
		return rich_to_ansi(s)
