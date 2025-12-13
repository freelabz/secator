import time
from typing import Dict, List
from pydantic import Field
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, traceback_as_string, rich_escape as _s


class Error(OutputType):
	message: str
	traceback: str = ''
	traceback_title: str = ''
	_source: str = ''
	_type: str = 'error'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = ['message', 'traceback']
	_sort_by = ('_timestamp',)

	def from_exception(e, **kwargs):
		errtype = type(e).__name__
		if str(e):
			errtype += f': {str(e)}'
		message = kwargs.pop('message', errtype)
		traceback = traceback_as_string(e) if errtype not in ['KeyboardInterrupt', 'GreenletExit'] else ''
		error = Error(message=_s(message), traceback=traceback, **kwargs)
		return error

	def __str__(self):
		return self.message

	def __repr__(self):
		s = rf"\[[bold red]ERR[/]] {self.message}"
		if self.traceback:
			traceback_pretty = '   ' + _s(self.traceback).replace('\n', '\n   ')
			if self.traceback_title:
				traceback_pretty = f'   {self.traceback_title}:\n{traceback_pretty}'
			s += f'\n[dim]{_s(traceback_pretty)}[/]'
		return rich_to_ansi(s)
