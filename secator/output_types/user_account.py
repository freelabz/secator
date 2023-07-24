from dataclasses import dataclass, field

from secator.definitions import USERNAME, URL, SITE_NAME
from secator.output_types import OutputType
from colorama import Fore


@dataclass
class UserAccount(OutputType):
	site_name: str
	username: str
	url: str = ''
	email: str = ''
	extra_data: dict = field(default_factory=dict, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='user_account', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = [SITE_NAME, USERNAME, URL]
	_sort_by = (URL, USERNAME)
	_raw_field = URL

	def __str__(self) -> str:
		return self.url

	def __repr__(self) -> str:
		s = f'👤 {Fore.GREEN}{self.site_name}{Fore.RESET}'
		if self.url:
			s += f' [{self.url}]'
		if self.extra_data:
			s += f' [{Fore.YELLOW}' + ', '.join(f'{k}:{v}' for k, v in self.extra_data.items()) + f'{Fore.RESET}]'
		return s
