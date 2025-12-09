import time
from typing import Dict, List
from pydantic import Field

from secator.definitions import HOST, NAME, TYPE
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


class Record(OutputType):
	name: str
	type: str
	host: str = ''
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'record'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = [NAME, HOST, TYPE]
	_sort_by = (TYPE, NAME)

	def __str__(self) -> str:
		return self.name

	def __repr__(self) -> str:
		s = rf'🎤 [bold white]{self.name}[/] \[[green]{self.type}[/]]'
		if self.host:
			s += rf' \[[magenta]{self.host}[/]]'
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')
		return rich_to_ansi(s)
