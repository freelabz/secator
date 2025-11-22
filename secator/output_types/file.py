import time
from dataclasses import dataclass, field

from secator.definitions import PATH
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


@dataclass
class File(OutputType):
	path: str
	category: str = field(default='general')
	tags: list = field(default_factory=list, compare=False)
	size: int = field(default=0, compare=False)
	mime_type: str = field(default='', compare=False)
	hash: str = field(default='', compare=False)
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True, compare=False)
	_type: str = field(default='file', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [PATH, 'category', 'tags', 'size', 'mime_type', 'hash']
	_sort_by = ('category', PATH)

	def __post_init__(self):
		super().__post_init__()

	def __str__(self) -> str:
		return self.path

	def __repr__(self) -> str:
		s = rf'📄 \[[bold white]{_s(self.path)}[/]]'
		if self.category:
			s += rf' \[[bold yellow]{self.category}[/]]'
		if self.mime_type:
			s += rf' \[[magenta]{self.mime_type}[/]]'
		if self.size:
			# Format size in human-readable format
			if self.size < 1024:
				size_str = f'{self.size}B'
			elif self.size < 1024 * 1024:
				size_str = f'{self.size / 1024:.1f}KB'
			elif self.size < 1024 * 1024 * 1024:
				size_str = f'{self.size / (1024 * 1024):.1f}MB'
			else:
				size_str = f'{self.size / (1024 * 1024 * 1024):.1f}GB'
			s += rf' \[[cyan]{size_str}[/]]'
		if self.hash:
			# Show abbreviated hash
			s += rf' \[[dim green]{self.hash[:16]}...[/]]'
		if self.tags:
			tags_str = ', '.join([f'[blue]{_s(tag)}[/]' for tag in self.tags])
			s += f' [{tags_str}]'
		if self.extra_data:
			extra_str = ', '.join([f'[dim yellow]{_s(k)}={_s(v)}[/]' for k, v in self.extra_data.items()])
			s += f' [{extra_str}]'
		return rich_to_ansi(s)
