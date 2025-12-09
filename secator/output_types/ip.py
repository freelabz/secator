import time
from enum import Enum
from typing import Dict, List
from pydantic import Field, ConfigDict

from secator.definitions import ALIVE, IP
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


class IpProtocol(str, Enum):
	IPv6 = 'IPv6'
	IPv4 = 'IPv4'


class Ip(OutputType):
	ip: str
	host: str = ''
	alive: bool = False
	protocol: str = IpProtocol.IPv4
	extra_data: Dict = Field(default_factory=dict)
	source_: str = Field(default='', alias='_source')
	type_: str = Field(default='ip', alias='_type')
	timestamp_: int = Field(default_factory=lambda: time.time(), alias='_timestamp')
	uuid_: str = Field(default='', alias='_uuid')
	context_: Dict = Field(default_factory=dict, alias='_context')
	tagged_: bool = Field(default=False, alias='_tagged')
	duplicate_: bool = Field(default=False, alias='_duplicate')
	related_: List = Field(default_factory=list, alias='_related')


# Class attributes (not model fields)
Ip._table_fields = [IP, ALIVE]
Ip._sort_by = (IP,)

	def __str__(self) -> str:
		return self.ip

	def __repr__(self) -> str:
		s = f'💻 [bold white]{self.ip}[/]'
		if self.host and self.host != self.ip:
			s += rf' \[[bold magenta]{self.host}[/]]'
		if self.alive:
			s += r' \[[bold green]alive[/]]'
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')
		if not self.alive:
			s = f'[dim]{s}[/]'
		return rich_to_ansi(s)
