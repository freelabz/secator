import time
from dataclasses import dataclass, field

from secator.definitions import (CONTENT_LENGTH, CONTENT_TYPE, STATUS_CODE,
								 TECH, TITLE, URL, WEBSERVER, METHOD)
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, trim_string, format_object, rich_escape as _s
from secator.config import CONFIG


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
	response_headers: dict = field(default_factory=dict, repr=True, compare=False)
	request_headers: dict = field(default_factory=dict, repr=True, compare=False)
	extra_data: dict = field(default_factory=dict, compare=False)
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
		METHOD,
		STATUS_CODE,
		TITLE,
		WEBSERVER,
		TECH,
		CONTENT_TYPE,
		CONTENT_LENGTH,
		'stored_response_path',
		'screenshot_path',
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
		s = f'🔗 [white]{_s(self.url)}'
		if self.method and self.method != 'GET':
			s += rf' \[[turquoise4]{self.method}[/]]'
		if self.request_headers:
			s += rf'{format_object(self.request_headers, "gold3", skip_keys=["user_agent"])}'
		if self.status_code and self.status_code != 0:
			if self.status_code < 400:
				s += rf' \[[green]{self.status_code}[/]]'
			else:
				s += rf' \[[red]{self.status_code}[/]]'
		if self.title:
			s += rf' \[[spring_green3]{trim_string(self.title)}[/]]'
		if self.webserver:
			s += rf' \[[bold magenta]{_s(self.webserver)}[/]]'
		if self.tech:
			techs_str = ', '.join([f'[magenta]{_s(tech)}[/]' for tech in self.tech])
			s += f' [{techs_str}]'
		if self.content_type:
			s += rf' \[[magenta]{_s(self.content_type)}[/]]'
		if self.content_length:
			cl = str(self.content_length)
			cl += '[bold red]+[/]' if self.content_length == CONFIG.http.response_max_size_bytes else ''
			s += rf' \[[magenta]{cl}[/]]'
		if self.response_headers and CONFIG.cli.show_http_response_headers:
			s += rf'{format_object(self.response_headers, "magenta", skip_keys=CONFIG.cli.exclude_http_response_headers)}'  # noqa: E501
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')
		if self.screenshot_path:
			s += rf' [link=file://{self.screenshot_path}]:camera:[/]'
		if self.stored_response_path:
			s += rf' [link=file://{self.stored_response_path}]:pencil:[/]'
		return rich_to_ansi(s)
