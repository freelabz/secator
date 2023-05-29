from dataclasses import dataclass, field

from secsy.output_types import OutputType
from colorama import Fore, Style


@dataclass
class Tag(OutputType):
	name: str
	match: str
	extra_data: dict = field(default_factory=dict, repr=True, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='tag', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = ['match', 'name', 'extra_data']
	_sort_by = ('match', 'name')

	def __post_init__(self):
		super().__post_init__()

	def __str__(self) -> str:
		cyan = Fore.CYAN
		reset = Style.RESET_ALL
		bright = Style.BRIGHT
		s = f'[{bright}{cyan}{self.name}{reset}] {self.match}'
		return s

	def __repr__(self) -> str:
		return str(self)
