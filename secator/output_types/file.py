import time
from dataclasses import dataclass, field
from typing import Literal

from secator.definitions import PATH
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s

VALID_FILE_TYPES = ('local', 'gcs')


@dataclass
class File(OutputType):
	path: str
	type: Literal['local', 'gcs'] = field(default='local')
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

	_table_fields = [PATH, 'type', 'category', 'tags', 'size', 'mime_type', 'hash']
	_sort_by = ('category', PATH)

	def __post_init__(self):
		if self.type not in VALID_FILE_TYPES:
			raise ValueError(f"File type must be one of {VALID_FILE_TYPES}, got {self.type!r}")
		super().__post_init__()

	def __str__(self) -> str:
		return self.path

	def __repr__(self) -> str:
		icon = '☁️' if self.type == 'gcs' else '📄'
		s = rf'{icon} \[[bold white]{_s(self.path)}[/]]'
		if self.category:
			s += rf' \[[bold yellow]{self.category}[/]]'
		if self.type != 'local':
			s += rf' \[[dim cyan]{self.type}[/]]'
		if self.mime_type:
			s += rf' \[[magenta]{self.mime_type}[/]]'
		if self.size:
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
			hash_display = f'{self.hash[:16]}...' if len(self.hash) > 16 else self.hash
			s += rf' \[[dim green]{hash_display}[/]]'
		if self.tags:
			tags_str = ', '.join([f'[blue]{_s(str(tag))}[/]' for tag in self.tags])
			s += f' [{tags_str}]'
		if self.extra_data:
			extra_str = ', '.join([f'[dim yellow]{_s(str(k))}={_s(str(v))}[/]' for k, v in self.extra_data.items()])
			s += f' [{extra_str}]'
		return rich_to_ansi(s)
