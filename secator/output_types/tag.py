import time
from typing import Dict, List
from pydantic import Field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, trim_string, rich_escape as _s


class Tag(OutputType):
	name: str
	value: str
	match: str
	category: str = 'general'
	extra_data: Dict = Field(default_factory=dict)
	stored_response_path: str = ''
	_source: str = ''
	_type: str = 'tag'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = ['match', 'category', 'name', 'extra_data']
	_sort_by = ('match', 'name')

	def __str__(self) -> str:
		return self.match

	def __repr__(self) -> str:
		content = self.value
		s = rf'🏷️  \[[bold yellow]{self.category}[/]] [bold magenta]{self.name}[/]'
		small_content = False
		if len(content) < 100:
			small_content = True
		# content_xs = trim_string(content, max_length=50).replace('\n', '/')
		if small_content:
			s += f' [bold orange4]{content}[/]'
		if self.match != content:
			s += f' found @ [bold]{_s(self.match)}[/]'
		ed = ''
		if self.stored_response_path:
			s += rf' [link=file://{self.stored_response_path}]:incoming_envelope:[/]'
		if not small_content:
			sep = ' '
			content = trim_string(content, max_length=1000)
			content = content.replace('\n', '\n    ')
			sep = '\n    '
			ed += f'\n    [bold red]value[/]:{sep}[yellow]{_s(content)}[/]'
		if self.extra_data:
			for k, v in self.extra_data.items():
				sep = ' '
				if not v:
					continue
				if isinstance(v, str):
					v = trim_string(v, max_length=1000)
					if len(v) > 1000:
						v = v.replace('\n', '\n' + sep)
						sep = '\n    '
				if k == 'content' and not small_content:
					ed += f'\n    [bold red]{_s(k)}[/]:{sep}[yellow]{_s(v)}[/]'
				else:
					ed += f'\n    [dim red]{_s(k)}[/]:{sep}[dim yellow]{_s(v)}[/]'
		if ed:
			s += ed
		return rich_to_ansi(s)
