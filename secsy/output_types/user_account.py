import re

from secsy.output_types import OutputType
from secsy.definitions import USER_ACCOUNT, URL

from dataclasses import dataclass, field

class UserAccount(OutputType):
    user_account: str
    url: str
    _source: str = field(default='', repr=True)
    _type: str = field(default='', repr=True)

    _table_fields = []
    _sort_by = (USER_ACCOUNT,)

    def __repr__(self) -> str:
        return f'{self.host}:{self.port}'