from dataclasses import dataclass, field

from secator.definitions import NAME, HOST, TYPE
from secator.output_types import OutputType
from colorama import Fore, Style


@dataclass
class Record(OutputType):
	name: str
	type: str
	host: str = ''
	_source: str = field(default='', repr=True)
	_type: str = field(default='record', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = [NAME, HOST, TYPE]
	_sort_by = (TYPE, NAME)

	def __str__(self) -> str:
		return self.name

	def __repr__(self) -> str:
		white = Fore.WHITE
		reset = Style.RESET_ALL
		bright = Style.BRIGHT
		magenta = Fore.MAGENTA
		green = Fore.GREEN
		return f'🎤 {bright}{white}{self.host}{reset} [{magenta}{self.name}{reset}] [{green}{self.type}{reset}]'
