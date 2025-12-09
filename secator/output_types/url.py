import time
from typing import Dict, List
from urllib.parse import urlparse
from pydantic import Field, model_validator

from secator.definitions import (CONTENT_LENGTH, CONTENT_TYPE, STATUS_CODE,
								 TECH, TITLE, URL, WEBSERVER, METHOD)
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, trim_string, format_object, rich_escape as _s
from secator.config import CONFIG


class Url(OutputType):
	url: str
	host: str = ''
	verified: bool = False
	status_code: int = 0
	title: str = ''
	webserver: str = ''
	tech: List = Field(default_factory=list)
	content_type: str = ''
	content_length: int = 0
	time: str = ''
	method: str = ''
	words: int = 0
	lines: int = 0
	screenshot_path: str = ''
	stored_response_path: str = ''
	response_headers: Dict = Field(default_factory=dict)
	request_headers: Dict = Field(default_factory=dict)
	is_directory: str = ''
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'url'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

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

	@model_validator(mode='after')
	def set_computed_fields(self):
		if not self.host:
			self.host = urlparse(self.url).hostname
		if self.status_code != 0:
			self.verified = True
		if self.title and 'Index of' in self.title:
			self.is_directory = True
		return self

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
		if self.is_directory:
			s += r' \[[bold gold3]directory[/]]'
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
		if not self.verified:
			s = f'[dim]{s}[/]'
		return rich_to_ansi(s)
