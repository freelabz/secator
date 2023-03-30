from dataclasses import dataclass, field

from secsy.definitions import *
from secsy.output_types import OutputType


@dataclass
class Ip(OutputType):
	ip: str
	host: str = ''
	alive: bool = False
	_source: str = field(default='', repr=True)
	_type: str = field(default='ip', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = [IP, ALIVE]
	_sort_by = (IP,)

	def __str__(self) -> str:
		return self.ip