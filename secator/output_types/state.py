import time
from typing import Dict, List
from pydantic import Field

from secator.output_types._base import OutputType
from secator.utils import rich_to_ansi


class State(OutputType):
	"""Represents the state of a Celery task."""

	task_id: str
	state: str
	_type: str = 'state'
	_source: str = ''
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)
	_icon = '📊'
	_color = 'bright_blue'

	def __str__(self) -> str:
		return f"Task {self.task_id} is {self.state}"

	def __repr__(self) -> str:
		return rich_to_ansi(f"{self._icon} [bold {self._color}]{self.state}[/] {self.task_id}")
