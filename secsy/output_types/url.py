from secsy.output_types import OutputType
from dataclasses import dataclass, field
from secsy.definitions import URL, STATUS_CODE, TITLE, WEBSERVER, TECH, CONTENT_TYPE, TIME

class URL(OutputType):
	url: str
	host: str = ''
	status_code: int = 0
	title: str = ''
	webserver: str = ''
	tech: list = field(default_factory=list)
	content_type: str = ''
	content_length: int = 0
	time: str = ''
	method: str = ''
	words: int = 0
	lines: int = 0
	_source: str = field(default='', repr=True)
	_type: str = field(default='', repr=True)

	_output_field = URL
	_table_fields = [
		URL,
		STATUS_CODE,
		TITLE,
		WEBSERVER,
		TECH,
		CONTENT_TYPE,
		TIME
	]
	_sort_by = (URL,)