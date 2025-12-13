import time
from typing import Dict, List
from pydantic import Field, model_validator

from secator.output_types import OutputType
from secator.utils import autodetect_type, rich_to_ansi, rich_escape as _s


class Target(OutputType):
	name: str
	type: str = ''
	_source: str = ''
	_type: str = 'target'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = [
		'name',
		'type',
	]
	_sort_by = ('type', 'name')

	@model_validator(mode='after')
	def set_type(self):
		if not self.type:
			self.type = autodetect_type(self.name)
		return self

	def __str__(self):
		return self.name

	def __repr__(self):
		s = f'🎯 {_s(self.name)}'
		if self.type:
			s += f' ({self.type})'
		return rich_to_ansi(s)
