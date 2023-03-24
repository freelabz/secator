from secsy.output_types import OutputType
from secsy.definitions import PORT, HOST, IP
from dataclasses import dataclass, field


@dataclass
class Port(OutputType):
	port: int
	host: str
	ip: str = ''
	_source: str = field(default='', repr=True)
	_type: str = field(default='', repr=True)

	_table_fields = [HOST, PORT]
	_sort_by = (HOST, PORT)

	def __repr__(self) -> str:
		return f'{self.host}:{self.port}'