import time
from dataclasses import dataclass, field

from secator.output_types import OutputType
from secator.utils import rich_to_ansi, trim_string, rich_escape as _s


@dataclass
class Tag(OutputType):
	name: str
	value: str
	match: str
	category: str = field(default='general')
	extra_data: dict = field(default_factory=dict, repr=True, compare=False)
	stored_response_path: str = field(default='', compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='tag', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = ['match', 'category', 'name', 'extra_data']
	_sort_by = ('match', 'name')

	def __post_init__(self):
		super().__post_init__()

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
