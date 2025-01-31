import time
from dataclasses import dataclass, field

from secator.definitions import SITE_NAME, URL, USERNAME
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s


@dataclass
class UserAccount(OutputType):
	username: str
	url: str = ''
	email: str = ''
	site_name: str = ''
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='user_account', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [SITE_NAME, USERNAME, URL]
	_sort_by = (URL, USERNAME)

	def __str__(self) -> str:
		return self.url

	def __repr__(self) -> str:
		s = f'👤 [green]{_s(self.username)}[/]'
		if self.email:
			s += rf' \[[bold yellow]{_s(self.email)}[/]]'
		if self.site_name:
			s += rf' \[[bold blue]{self.site_name}[/]]'
		if self.url:
			s += rf' \[[white]{_s(self.url)}[/]]'
		if self.extra_data:
			s += r' \[[bold yellow]' + _s(', '.join(f'{k}:{v}' for k, v in self.extra_data.items()) + '[/]]')
		return rich_to_ansi(s)
