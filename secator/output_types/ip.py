import time
from dataclasses import dataclass, field

from colorama import Fore, Style

from secator.definitions import ALIVE, IP
from secator.output_types import OutputType


@dataclass
class Ip(OutputType):
	ip: str
	host: str = ''
	alive: bool = False
	_source: str = field(default='', repr=True)
	_type: str = field(default='ip', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = [IP, ALIVE]
	_sort_by = (IP,)

	def __str__(self) -> str:
		return self.ip

	def __repr__(self) -> str:
		white = Fore.WHITE
		reset = Style.RESET_ALL
		bright = Style.BRIGHT
		magenta = Fore.MAGENTA
		s = f'💻 {bright}{white}{self.ip}{reset}'
		if self.host:
			s += f' [{magenta}{self.host}{reset}]'
		return s
