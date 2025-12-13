import time
from typing import Dict, List
from pydantic import Field, model_validator
from secator.output_types import OutputType
from secator.utils import strip_rich_markup, rich_to_ansi


class Warning(OutputType):
	message: str
	message_color: str = ''
	task_id: str = ''
	_source: str = ''
	_type: str = 'warning'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = ['task_name', 'message']
	_sort_by = ('_timestamp',)

	@model_validator(mode='after')
	def set_message_color(self):
		self.message_color = self.message
		self.message = strip_rich_markup(self.message)
		return self

	def __repr__(self):
		s = rf"\[[yellow]WRN[/]] {self.message_color}"
		return rich_to_ansi(s)
