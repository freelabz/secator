import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Stat(OutputType):
	name: str
	pid: int
	cpu: int
	memory: int
	net_conns: int = field(default=None, repr=True)
	extra_data: dict = field(default_factory=dict)
	_source: str = field(default='', repr=True)
	_type: str = field(default='stat', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['name', 'pid', 'cpu', 'memory']
	_sort_by = ('name', 'pid')

	def __repr__(self) -> str:
		s = rf'[dim yellow3]📊 {self.name} \[pid={self.pid}] \[cpu={self.cpu:.2f}%] \[memory={self.memory:.2f}%]'
		if self.net_conns:
			s += rf' \[connections={self.net_conns}]'
		s += ' [/]'
		return rich_to_ansi(s)
