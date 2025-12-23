import time
from datetime import datetime
from typing import Dict, List
from pydantic import Field

from secator.definitions import ALIVE, DOMAIN
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


class Domain(OutputType):
	domain: str
	registrar: str = ''
	alive: bool = False
	creation_date: str = ''
	expiration_date: str = ''
	registrant: str = ''
	extra_data: Dict = Field(default_factory=dict)
	_source: str = ''
	_type: str = 'domain'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)

	_table_fields = [DOMAIN, ALIVE]
	_sort_by = (DOMAIN,)

	def __str__(self) -> str:
		return self.domain

	def __repr__(self) -> str:
		s = f'🪪  [bold white]{self.domain}[/]'
		if self.registrant:
			s += rf' \[[bold magenta]{self.registrant}[/]]'
		if self.registrar:
			s += rf' \[[bold blue]{self.registrar}[/]]'
		if self.expiration_date:
			now = datetime.now()
			expiration_date_strptime = datetime.strptime(self.expiration_date, "%Y-%m-%d %H:%M:%S")
			if expiration_date_strptime < now:
				s += rf' \[[bold red]{self.expiration_date}[/]]'
			else:
				s += rf' \[[bold green]{self.expiration_date}[/]]'
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')

		return rich_to_ansi(s)
