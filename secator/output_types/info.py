import time
from typing import Dict, List
from pydantic import Field
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


class Info(OutputType):
	message: str
	task_id: str = ''
	_source: str = ''
	_type: str = 'info'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = ['message', 'task_id']
	_sort_by = ('_timestamp',)

	def __repr__(self):
		s = rf"\[[blue]INF[/]] {self.message}"
		return rich_to_ansi(s)
