import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from secator.output_types import OutputType
from secator.utils import rich_to_ansi
from secator.definitions import CERTIFICATE_STATUS_UNKNOWN


@dataclass
class Certificate(OutputType):
    host: str
    fingerprint_sha256: str = field(default='')
    ip: str = field(default='', compare=False)
    raw_value: str = field(default='', compare=False)
    subject_cn: str = field(default='', compare=False)
    subject_an: list[str] = field(default_factory=list, compare=False)
    not_before: datetime = field(default=None, compare=False)
    not_after: datetime = field(default=None, compare=False)
    issuer_dn: str = field(default='', compare=False)
    issuer_cn: str = field(default='', compare=False)
    issuer: str = field(default='', compare=False)
    self_signed: bool = field(default=True, compare=False)
    trusted: bool = field(default=False, compare=False)
    status: str = field(default=CERTIFICATE_STATUS_UNKNOWN, compare=False)
    keysize: int = field(default=None, compare=False)
    serial_number: str = field(default='', compare=False)
    ciphers: list[str] = field(default_factory=list, compare=False)
    # parent_certificate: 'Certificate' = None  # noqa: F821
    _source: str = field(default='', repr=True)
    _type: str = field(default='certificate', repr=True)
    _timestamp: int = field(default_factory=lambda: time.time(), compare=False)
    _uuid: str = field(default='', repr=True, compare=False)
    _context: dict = field(default_factory=dict, repr=True, compare=False)
    _tagged: bool = field(default=False, repr=True, compare=False)
    _duplicate: bool = field(default=False, repr=True, compare=False)
    _related: list = field(default_factory=list, compare=False)
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
