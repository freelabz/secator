from dataclasses import dataclass, field

from secsy.definitions import USERNAME, URL, SITE_NAME
from secsy.output_types import OutputType

@dataclass
class UserAccount(OutputType):
	site_name: str
	username: str
	url: str = ''
	_source: str = field(default='', repr=True)
	_type: str = field(default='', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = [SITE_NAME, USERNAME, URL]
	_sort_by = (URL, USERNAME)

	def __repr__(self) -> str:
		return f'{self.site_name} -> {self.username}'