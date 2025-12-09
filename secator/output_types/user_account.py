import time
from typing import Dict, List
from pydantic import Field

from secator.definitions import SITE_NAME, URL, USERNAME
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, rich_escape as _s, format_object


class UserAccount(OutputType):
	username: str
	url: str = ''
	email: str = ''
	site_name: str = ''
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'user_account'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

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
			s += format_object(self.extra_data, 'yellow')
		return rich_to_ansi(s)
