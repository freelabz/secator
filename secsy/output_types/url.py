from dataclasses import dataclass, field

from secsy.definitions import URL, STATUS_CODE, TITLE, WEBSERVER, TECH, CONTENT_TYPE, CONTENT_LENGTH, TIME
from secsy.output_types import OutputType


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

	# def __str__(self):
	# 	s = f'{self.url}'
	# 	if self.status_code and self.status_code != 0:
	# 		s += f' [{self.status_code}]'
	# 	if self.title:
	# 		s += f' [{self.title}]'
	# 	if self.webserver:
	# 		s += f' [{self.webserver}]'
	# 	if self.tech:
	# 		s += f' {self.tech}'
	# 	if self.content_type:
	# 		s += f' [{self.content_type}]'
	# 	return s
