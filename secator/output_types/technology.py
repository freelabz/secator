import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_escape as _s
from secator.utils import rich_to_ansi


@dataclass
class Technology(OutputType):
	product: str
	match: str
	version: str = None
	extra_data: dict = field(default_factory=dict, repr=True, compare=False)
	tags: list = field(default_factory=list, compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='technology', repr=True)
	_timestamp: float = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['match', 'product', 'version', 'extra_data']
	_sort_by = ('match', 'product', 'version')

	def __str__(self) -> str:
		return self.match

	def __rich__(self) -> str:
		s = '📦 '
		s += f'[bold orange3]{_s(self.product)}[/]'
		if self.version:
			s += f'/[red]{self.version}[/]'
		s += f' found @ {self.match}'
		if self.extra_data:
			ed = ''
			for k, v in self.extra_data.items():
				sep = ' '
				if not v:
					continue
				ed += f'\n    [bold red]{_s(k)}[/]:{sep}[yellow]{_s(v)}[/]'
			s += ed
		return s

	def __repr__(self) -> str:
		return rich_to_ansi(self.__rich__())
