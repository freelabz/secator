import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


@dataclass
class Progress(OutputType):
	percent: int = 0
	extra_data: dict = field(default_factory=dict)
	_source: str = field(default='', repr=True)
	_type: str = field(default='progress', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['percent']
	_sort_by = ('percent',)

	def __post_init__(self):
		super().__post_init__()
		if not 0 <= self.percent <= 100:
			self.percent = 0

	def __str__(self) -> str:
		return f'{self.percent}%'

	def __repr__(self) -> str:
		s = f'[dim]⏳ [bold]{self.percent}%[/] ' + '█' * (self.percent // 10) + '[/]'
		ed = format_object(self.extra_data, color='yellow3', skip_keys=['startedAt'])
		s += f'[dim]{ed}[/]'
		return rich_to_ansi(s)
