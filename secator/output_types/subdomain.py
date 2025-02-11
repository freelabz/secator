import time
from dataclasses import dataclass, field
from typing import List

from secator.definitions import DOMAIN, HOST, SOURCES
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Subdomain(OutputType):
	host: str
	domain: str
	sources: List[str] = field(default_factory=list, compare=False)
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='subdomain', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

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
			s += r' \[[bold yellow]' + ', '.join(f'{k}:{v}' for k, v in self.extra_data.items()) + '[/]]'
		return rich_to_ansi(s)
