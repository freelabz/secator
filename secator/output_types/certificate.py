import time
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum, auto
from secator.output_types import OutputType
from secator.utils import rich_to_ansi


class Certificate_status(Enum):
    REVOKED = auto()  # noqa: F821
    TRUSTED = auto()  # noqa: F821
    UNKOWN = auto()  # noqa: F821


@dataclass
class Certificate(OutputType):
    ip: str = ''
    host: str = ''
    fingerprint_sha256: str = ''
    subject_cn: str = ''
    subject_an: list[str] = field(default_factory=list)
    not_before: datetime = None
    not_after: datetime = None
    issuer_dn: str = ''
    issuer_cn: str = ''
    issuer: str = ''
    self_signed: bool = True
    trusted: bool = False
    status: Certificate_status = Certificate_status.UNKOWN
    keysize: int = None
    serial_number: str = ''
    ciphers: list[str] = field(default_factory=list)
    parent_certificate: 'Certificate' = None  # noqa: F821
    _source: str = field(default='', repr=True)
    _type: str = field(default='ip', repr=True)
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
            return self.not_after > datetime.now()
        return True

    def __repr__(self) -> str:
        s = f'📜 [bold white]{self.host}[/]'
        if self.subject_cn:
            s += f' [white]Subject cn : {self.subject_cn}'
        if self.subject_an:
            s += f' [white]Subject an : {', '.join(self.subject_an)}'
        if self.is_expired():
            s += f' [red] expired since {self.not_after.strftime('%m %d %Y')}'
        else:
            s += f' [green] not expired until {self.not_after.strftime('%m %d %Y')}'
        if self.issuer:
            s += f'[white] issuer : {self.issuer}'
        s += f'[white] {self.status}'
        return rich_to_ansi(s)
