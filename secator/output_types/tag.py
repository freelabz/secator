import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Tag(OutputType):
	name: str
	match: str
	extra_data: dict = field(default_factory=dict, repr=True, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='tag', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['match', 'name', 'extra_data']
	_sort_by = ('match', 'name')

	def __post_init__(self):
		super().__post_init__()

	def __str__(self) -> str:
		return self.match

	def __repr__(self) -> str:
		s = f'🏷️  [bold magenta]{self.name}[/]'
		s += f' found @ [bold]{self.match}[/]'
		ed = ''
		if self.extra_data:
			for k, v in self.extra_data.items():
				sep = ' '
				if not v:
					continue
				if len(v) >= 80:
					v = v.replace('\n', '\n' + '  ').replace('...TRUNCATED', '\n[italic bold red]...truncated to 1000 chars[/]')
					sep = '\n    '
				ed += f'\n    [dim red]{k}[/]:{sep}[dim yellow]{v}[/]'
		if ed:
			s += ed
		return rich_to_ansi(s)
