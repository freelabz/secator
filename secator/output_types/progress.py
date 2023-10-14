import time
from dataclasses import dataclass, field

from secator.definitions import DEBUG
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Progress(OutputType):
	duration: str
	percent: int
	errors: list = field(default_factory=list)
	extra_data: dict = field(default_factory=dict)
	_source: str = field(default='', repr=True)
	_type: str = field(default='metric', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = ['percent', 'duration']
	_sort_by = ('percent',)

	def __str__(self) -> str:
		return f'{self.percent}%'

	def __repr__(self) -> str:
		s = f'[dim]⏳ {self.percent}% ' + '█' * (self.percent // 10) + '[/]'
		if self.errors:
			s += f' [dim red]errors={self.errors}[/]'
		if DEBUG > 1:
			ed = ' '.join([f'{k}={v}' for k, v in self.extra_data.items() if k != 'startedAt' and v])
			s += f' [dim yellow]{ed}[/]'
		return rich_to_ansi(s)
