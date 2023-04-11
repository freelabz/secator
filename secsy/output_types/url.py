from dataclasses import dataclass, field

from secsy.definitions import URL, STATUS_CODE, TITLE, WEBSERVER, TECH, CONTENT_TYPE, CONTENT_LENGTH, TIME
from secsy.output_types import OutputType


@dataclass
class Url(OutputType):
	url: str
	host: str = field(default='', compare=False)
	status_code: int = 0
	title: str = ''
	webserver: str = ''
	tech: list = field(default_factory=list)
	content_type: str = ''
	content_length: int = 0
	time: str = field(default='', compare=False)
	method: str = ''
	words: int = 0
	lines: int = 0
	_source: str = field(default='', repr=True)
	_type: str = field(default='url', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)

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
