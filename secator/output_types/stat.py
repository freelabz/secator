import time
from typing import Dict, List, Optional
from pydantic import Field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi


class Stat(OutputType):
	name: str
	pid: int
	cpu: int
	memory: int
	memory_limit: int
	net_conns: Optional[int] = None
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'stat'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = ['name', 'pid', 'cpu', 'memory']
	_sort_by = ('name', 'pid')

	def __str__(self) -> str:
		return f'{self.name} ([bold]pid[/]:{self.pid}) ([bold]cpu[/]:{self.cpu:.2f}%) ([bold]memory[/]:{self.memory:.2f}MB / {self.memory_limit}MB)'  # noqa: E501

	def __repr__(self) -> str:
		s = rf'[dim yellow3]📊 {self.name} ([bold]pid[/]:{self.pid}) ([bold]cpu[/]:{self.cpu:.2f}%)'
		s += rf' ([bold]memory[/]:{self.memory:.2f}MB'
		if self.memory_limit != -1:
			s += rf' / {self.memory_limit}MB'
		s += ')'
		if self.net_conns:
			s += rf' ([bold]connections[/]:{self.net_conns})'
		s += ' [/]'
		return rich_to_ansi(s)
