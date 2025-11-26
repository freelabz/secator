from dataclasses import dataclass, field
import time
from secator.output_types import OutputType
from secator.utils import strip_rich_markup, rich_to_ansi


@dataclass
class Warning(OutputType):
	message: str
	message_color: str = field(default='', compare=False)
	task_id: str = field(default='', compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='warning', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['task_name', 'message']
	_sort_by = ('_timestamp',)

	def __post_init__(self):
		super().__post_init__()
		self.message_color = self.message
		self.message = strip_rich_markup(self.message)

	def __repr__(self):
		s = rf"\[[yellow]WRN[/]] {self.message_color}"
		return rich_to_ansi(s)
