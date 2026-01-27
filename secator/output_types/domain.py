import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from secator.definitions import ALIVE, DOMAIN
from secator.config import CONFIG
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


@dataclass
class Domain(OutputType):
	domain: str
	registrar: str = ''
	alive: bool = False
	creation_date: str = ''
	expiration_date: str = ''
	registrant: str = ''
	extra_data: dict = field(default_factory=dict, compare=False)
	is_false_positive: bool = field(default=False, compare=False)
	is_acknowledged: bool = field(default=False, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='domain', repr=True)
	_timestamp: int = field(default_factory=lambda: time.time(), compare=False)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)
	_tagged: bool = field(default=False, repr=True, compare=False)
	_duplicate: bool = field(default=False, repr=True, compare=False)
	_related: list = field(default_factory=list, compare=False)

	_table_fields = [DOMAIN, ALIVE]
	_sort_by = (DOMAIN,)

	def is_expired(self, months=0) -> bool:
		if self.expiration_date:
			expiry_date = datetime.strptime(self.expiration_date, "%Y-%m-%d %H:%M:%S")
			return expiry_date < datetime.now() + timedelta(days=months * 30)
		return True

	def __str__(self) -> str:
		return self.domain

	def __repr__(self) -> str:
		s = f'🪪  [bold white]{self.domain}[/]'
		if self.registrant:
			s += rf' \[[bold magenta]{self.registrant}[/]]'
		if self.registrar:
			s += rf' \[[bold blue]{self.registrar}[/]]'
		expiry_date = datetime.strptime(self.expiration_date, "%Y-%m-%d %H:%M:%S").strftime(CONFIG.cli.date_format)
		if self.is_expired():
			s += rf' \[[red][bold]expired[/] since {expiry_date}[/]]'
		elif self.is_expired(months=2):
			s += rf' \[[red][bold]expires soon[/] on {expiry_date}[/]]'
		else:
			s += rf' \[[green][bold]expires on[/] {expiry_date}[/]]'
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow')

		return rich_to_ansi(s)
