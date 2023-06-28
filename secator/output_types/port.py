from dataclasses import dataclass, field

from secator.definitions import PORT, HOST, IP, EXTRA_DATA, CPES
from secator.output_types import OutputType
from colorama import Fore, Style


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
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = [IP, PORT, HOST, CPES, EXTRA_DATA]
	_sort_by = (PORT, IP)

	def __str__(self) -> str:
		return f'{self.host}:{self.port}'

	def __repr__(self) -> str:
		white = Fore.WHITE
		reset = Style.RESET_ALL
		s = f'{white}{self.host}:{self.port}{reset}'
		if self.service_name:
			s += f' [{self.service_name}]'
		return s
