from dataclasses import dataclass, field

from secsy.definitions import URL, STATUS_CODE, TITLE, WEBSERVER, TECH, CONTENT_TYPE, CONTENT_LENGTH, TIME
from secsy.output_types import OutputType
from colorama import Fore, Style


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
	_source: str = field(default='', repr=True)
	_type: str = field(default='url', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

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
	_raw_field = URL

	def __str__(self):
		return self.url

	def __repr__(self):
		white = Fore.WHITE
		green = Fore.GREEN
		red = Fore.RED
		cyan = Fore.CYAN
		magenta = Fore.MAGENTA
		reset = Style.RESET_ALL
		s = f'{white}{self.url}'
		if self.status_code and self.status_code != 0:
			if self.status_code < 400:
				s += f' [{green}{self.status_code}{reset}]'
			else:
				s += f' [{red}{self.status_code}{reset}]'
		if self.title:
			s += f' [{green}{self.title}{reset}]'
		if self.webserver:
			s += f' [{cyan}{self.webserver}{reset}]'
		if self.tech:
			techs_str = ', '.join([f'{magenta}{tech}{reset}' for tech in self.tech])
			s += f' [{techs_str}]'
		if self.content_type:
			s += f' [{cyan}{self.content_type}{reset}]'
		return s
