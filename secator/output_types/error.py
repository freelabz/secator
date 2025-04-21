from dataclasses import dataclass, field
import time
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, traceback_as_string, rich_escape as _s


@dataclass
class Error(OutputType):
	message: str
	traceback: str = field(default='', compare=False)
	traceback_title: str = field(default='', compare=False)
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
		errtype = type(e).__name__
		message = errtype
		if str(e):
			message += f': {str(e)}'
		traceback = traceback_as_string(e) if errtype not in ['KeyboardInterrupt', 'GreenletExit'] else ''
		error = Error(message=message, traceback=traceback, **kwargs)
		return error

	def __str__(self):
		return self.message

	def __repr__(self):
		s = rf"\[[bold red]ERR[/]] {_s(self.message)}"
		if self.traceback:
			s += ':'
			traceback_pretty = '   ' + _s(self.traceback).replace('\n', '\n   ')
			if self.traceback_title:
				traceback_pretty = f'   {self.traceback_title}:\n{traceback_pretty}'
			s += f'\n[dim]{_s(traceback_pretty)}[/]'
		return rich_to_ansi(s)
