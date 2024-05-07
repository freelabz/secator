import time
from dataclasses import dataclass, field

from secator.definitions import (CONTENT_LENGTH, CONTENT_TYPE, STATUS_CODE,
								 TECH, TIME, TITLE, URL, WEBSERVER)
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


@dataclass
class Url(OutputType):
	url: str
	host: str = field(default='', compare=False)
	status_code: int = field(default=0, compare=False)
	title: str = field(default='', compare=False)
	webserver: str = field(default='', compare=False)
	tech: list = field(default_factory=list, compare=False)
	content_type: str = field(default='', compare=False)
	content_length: int = field(default=0, compare=False)
	time: str = field(default='', compare=False)
	method: str = field(default='', compare=False)
	words: int = field(default=0, compare=False)
	lines: int = field(default=0, compare=False)
	screenshot_path: str = field(default='', compare=False)
	stored_response_path: str = field(default='', compare=False)
	headers: dict = field(default_factory=dict, repr=True, compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='url', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [
		URL,
		STATUS_CODE,
		TITLE,
		WEBSERVER,
		TECH,
		CONTENT_TYPE,
		CONTENT_LENGTH,
		TIME
	]
	_sort_by = (URL,)

	def __gt__(self, other):
		# favor httpx over other url info tools
		if self._source == 'httpx' and other._source != 'httpx':
			return True
		return super().__gt__(other)

	def __str__(self):
		return self.url

	def __repr__(self):
		s = f'🔗 [white]{self.url}'
		if self.method and self.method != 'GET':
			s += f' \[[turquoise4]{self.method}[/]]'
		if self.status_code and self.status_code != 0:
			if self.status_code < 400:
				s += f' \[[green]{self.status_code}[/]]'
			else:
				s += f' \[[red]{self.status_code}[/]]'
		if self.title:
			s += f' \[[green]{self.title}[/]]'
		if self.webserver:
			s += f' \[[magenta]{self.webserver}[/]]'
		if self.tech:
			techs_str = ', '.join([f'[magenta]{tech}[/]' for tech in self.tech])
			s += f' [{techs_str}]'
		if self.content_type:
			s += f' \[[magenta]{self.content_type}[/]]'
		if self.content_length:
			s += f' \[[magenta]{self.content_length}[/]]'
		if self.screenshot_path:
			s += f' \[[magenta]{self.screenshot_path}[/]]'
		return rich_to_ansi(s)
