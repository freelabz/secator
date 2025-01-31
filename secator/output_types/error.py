from dataclasses import dataclass, field
import time
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, traceback_as_string, rich_escape as _s


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

	def from_exception(e, **kwargs):
		message = type(e).__name__
		if str(e):
			message += f': {str(e)}'
		return Error(message=message, traceback=traceback_as_string(e), **kwargs)

	def __str__(self):
		return self.message

	def __repr__(self):
		s = rf"\[[bold red]ERR[/]] {_s(self.message)}"
		if self.traceback:
			traceback_pretty = '   ' + self.traceback.replace('\n', '\n   ')
			s += f'\n[dim]{_s(traceback_pretty)}[/]'
		return rich_to_ansi(s)
