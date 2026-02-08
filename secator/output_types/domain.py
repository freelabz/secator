import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field

from secator.definitions import ALIVE, DOMAIN
from secator.config import CONFIG
from secator.output_types import OutputType
from secator.utils import rich_to_ansi, format_object


@dataclass
class Domain(OutputType):
	domain: str
	alive: bool = False
	creation_date: datetime = field(default=None, compare=False)
	expiration_date: datetime = field(default=None, compare=False)
	updated_date: datetime = field(default=None, compare=False)
	status: list = field(default_factory=list, compare=False)
	registrar: str = field(default='', compare=False)
	registrar_info: dict = field(default_factory=dict, compare=False)
	registrant: str = field(default='', compare=False)
	registrant_info: dict = field(default_factory=dict, compare=False)
	administrative_info: dict = field(default_factory=dict, compare=False)
	technical_info: dict = field(default_factory=dict, compare=False)
	extra_data: dict = field(default_factory=dict, compare=False)
	is_false_positive: bool = field(default=False, compare=False)
	is_acknowledged: bool = field(default=False, compare=False)
	tags: list = field(default_factory=list, compare=False)
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

	def __post_init__(self):
		super().__post_init__()
		self.creation_date = self.get_datetime(self.creation_date)
		self.expiration_date = self.get_datetime(self.expiration_date)
		self.updated_date = self.get_datetime(self.updated_date)
		if not self.alive and len(self.status) > 0:
			self.alive = 'active' in [s.lower() for s in self.status]

	@staticmethod
	def format_date(date):
		if date:
			return date.strftime(CONFIG.cli.date_format)
		return '?'

	@staticmethod
	def get_datetime(date):
		if isinstance(date, datetime):
			return date
		try:
			dt = datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
			dt = dt.replace(tzinfo=timezone.utc)
			return dt
		except (ValueError, TypeError):
			return None

	def is_expired(self, months=0) -> bool:
		if self.expiration_date:
			return self.expiration_date < datetime.now(timezone.utc) + timedelta(days=months * 30)
		return False

	def __str__(self) -> str:
		return self.domain

	def __repr__(self) -> str:
		s = f'🪪  [bold white]{self.domain}[/]'
		if self.alive:
			s += r' \[[bold green]alive[/]]'
		if self.registrant:
			s += rf' \[[bold magenta]{self.registrant}[/]]'
		if self.registrar:
			s += rf' \[[bold blue]{self.registrar}[/]]'
		expiry_date = self.format_date(self.expiration_date)
		if self.is_expired():
			s += rf' \[[red][bold]expired[/] since {expiry_date}[/]]'
		elif self.is_expired(months=2):
			s += rf' \[[red][bold]expires soon[/] on {expiry_date}[/]]'
		else:
			s += rf' \[[green][bold]expires on[/] {expiry_date}[/]]'
		if self.administrative_info:
			s += format_object(self.administrative_info, 'purple', predicate=lambda x: x)
		if self.extra_data:
			s += format_object(self.extra_data, 'yellow', predicate=lambda x: x)
		return rich_to_ansi(s)
