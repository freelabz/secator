from dataclasses import dataclass, field

from secsy.definitions import PORT, HOST, IP, EXTRA_DATA, CPES
from secsy.output_types import OutputType


@dataclass
class Port(OutputType):
	port: int
	host: str
	ip: str = ''
	service_name: str = ''
	cpes: list = field(default_factory=list)
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='port', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = [IP, PORT, HOST, CPES, EXTRA_DATA]
	_sort_by = (IP, PORT)

	def __str__(self) -> str:
		return f'{self.host}:{self.port}'

	def __post_init__(self):
		super().__post_init__()
		self.cpes = self.extra_data.get('cpe', [])
		self.service_name = self.extra_data.get('service_name', '')