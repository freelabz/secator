import time
from typing import Dict, List
from pydantic import Field

from secator.definitions import DOMAIN, HOST, SOURCES
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


class Subdomain(OutputType):
	host: str
	domain: str
	verified: bool = False
	sources: List[str] = Field(default_factory=list)
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'subdomain'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = [
		HOST,
		DOMAIN,
		SOURCES
	]
	_sort_by = (HOST,)

	def __str__(self):
		return self.host

	def __repr__(self):
		sources_str = ', '.join([f'[magenta]{source}[/]' for source in self.sources])
		s = f'🏰 [white]{self.host}[/]'
		if sources_str:
			s += f' [{sources_str}]'
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')
		if not self.verified:
			s = f'[dim]{s}[/]'
		return rich_to_ansi(s)
