import time
from typing import Dict, List
from pydantic import Field, model_validator

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


class Progress(OutputType):
	percent: int = 0
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'progress'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = ['percent']
	_sort_by = ('percent',)

	@model_validator(mode='after')
	def validate_percent(self):
		if not 0 <= self.percent <= 100:
			self.percent = 0
		return self

	def __str__(self) -> str:
		return f'{self.percent}%'

	def __repr__(self) -> str:
		s = f'[dim]⏳ [bold]{self.percent}%[/] ' + '█' * (self.percent // 10) + '[/]'
		ed = format_object(self.extra_data, color='yellow3', skip_keys=['startedAt'])
		s += f'[dim]{ed}[/]'
		return rich_to_ansi(s)
