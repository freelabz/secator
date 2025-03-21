import time
from dataclasses import dataclass, field

from secator.output_types._base import OutputType
from secator.utils import rich_to_ansi


@dataclass
class State(OutputType):
    """Represents the state of a Celery task."""

    task_id: str
    state: str
    _type: str = field(default='state', repr=True)
    _source: str = field(default='', repr=True)
    _timestamp: int = field(default_factory=lambda: time.time(), compare=False)
    _uuid: str = field(default='', repr=True, compare=False)
    _context: dict = field(default_factory=dict, repr=True, compare=False)
    _tagged: bool = field(default=False, repr=True, compare=False)
    _duplicate: bool = field(default=False, repr=True, compare=False)
    _related: list = field(default_factory=list, compare=False)
    _icon = '📊'
    _color = 'bright_blue'

    def __str__(self) -> str:
        return f"Task {self.task_id} is {self.state}"

    def __repr__(self) -> str:
        return rich_to_ansi(f"{self._icon} [bold {self._color}]{self.state}[/] {self.task_id}")
