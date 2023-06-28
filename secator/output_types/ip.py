from dataclasses import dataclass, field

from secator.definitions import ALIVE, IP
from secator.output_types import OutputType
from colorama import Fore, Style


@dataclass
class Ip(OutputType):
	ip: str
	host: str = ''
	alive: bool = False
	_source: str = field(default='', repr=True)
	_type: str = field(default='ip', repr=True)
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
		return f'{bright}{white}{self.ip}{reset} [{magenta}{self.host}{reset}]'
