from dataclasses import dataclass, field

from secsy.definitions import PORT, HOST, IP, EXTRA_DATA, CPES
from secsy.output_types import OutputType


@dataclass
class Port(OutputType):
	port: int
	host: str
	ip: str = ''
	cpes: list = field(default_factory=list)
	extra_data: dict = field(default_factory=dict)
	_source: str = field(default='', repr=True)
	_type: str = field(default='', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = [IP, PORT, HOST, CPES, EXTRA_DATA]
	_sort_by = (IP, PORT)

	def __repr__(self) -> str:
		return f'{self.host}:{self.port}'