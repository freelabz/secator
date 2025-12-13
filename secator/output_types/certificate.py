import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydantic import Field
from secator.output_types import OutputType
from secator.utils import rich_to_ansi
from secator.definitions import CERTIFICATE_STATUS_UNKNOWN


class Certificate(OutputType):
	host: str
	fingerprint_sha256: str = ''
	ip: str = ''
	raw_value: str = ''
	subject_cn: str = ''
	subject_an: List[str] = Field(default_factory=list)
	not_before: Optional[datetime] = None
	not_after: Optional[datetime] = None
	issuer_dn: str = ''
	issuer_cn: str = ''
	issuer: str = ''
	self_signed: bool = True
	trusted: bool = False
	status: str = CERTIFICATE_STATUS_UNKNOWN
	keysize: Optional[int] = None
	serial_number: str = ''
	ciphers: List[str] = Field(default_factory=list)
	# parent_certificate: 'Certificate' = None  # noqa: F821
	_source: str = ''
	_type: str = 'certificate'
	_timestamp: int = Field(default_factory=lambda: time.time())
	_uuid: str = ''
	_context: Dict = Field(default_factory=dict)
	_tagged: bool = False
	_duplicate: bool = False
	_related: List = Field(default_factory=list)
	_table_fields = ['ip', 'host']
	_sort_by = ('ip',)

	def __str__(self) -> str:
		return self.subject_cn

	def is_expired(self) -> bool:
		if self.not_after:
			return self.not_after < datetime.now()
		return True

	def is_expired_soon(self, months: int = 1) -> bool:
		if self.not_after:
			return self.not_after < datetime.now() + timedelta(days=months * 30)
		return True

	@staticmethod
	def format_date(date):
		if date:
			return date.strftime("%m/%d/%Y")
		return '?'

	def __repr__(self) -> str:
		s = f'📜 [bold white]{self.host}[/]'
		s += f' [cyan]{self.status}[/]'
		s += rf' [white]\[fingerprint={self.fingerprint_sha256[:10]}][/]'
		if self.subject_cn:
			s += rf' [white]\[cn={self.subject_cn}][/]'
		if self.subject_an:
			s += rf' [white]\[an={", ".join(self.subject_an)}][/]'
		if self.issuer:
			s += rf' [white]\[issuer={self.issuer}][/]'
		elif self.issuer_cn:
			s += rf' [white]\[issuer_cn={self.issuer_cn}][/]'
		expiry_date = Certificate.format_date(self.not_after)
		if self.is_expired():
			s += f' [red]expired since {expiry_date}[/red]'
		elif self.is_expired_soon(months=2):
			s += f' [yellow]expires <2 months[/yellow], [yellow]valid until {expiry_date}[/yellow]'
		else:
			s += f' [green]not expired[/green], [yellow]valid until {expiry_date}[/yellow]'
		return rich_to_ansi(s)
