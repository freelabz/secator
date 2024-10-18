from dataclasses import dataclass, field
import time
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Error(OutputType):
	message: str
	traceback: str = field(default='', compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='error', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['message', 'traceback']
	_sort_by = ('_timestamp',)

	def __repr__(self):
		s = f'[bold red]❌ {self._source}: {self.message}[/]'
		if self.traceback:
			traceback_pretty = '   ' + self.traceback.replace('\n', '\n   ')
			s += f'\n[dim]{traceback_pretty}[/]'
		return rich_to_ansi(s)
