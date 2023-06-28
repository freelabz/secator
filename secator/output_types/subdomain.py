from dataclasses import dataclass, field
from typing import List

from secator.definitions import DOMAIN, HOST, SOURCES
from secator.output_types import OutputType
from colorama import Fore, Style


@dataclass
class Subdomain(OutputType):
	host: str
	domain: str
	sources: List[str] = field(default_factory=list, compare=False)
	_source: str = field(default='', repr=True)
	_type: str = field(default='subdomain', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = [
		HOST,
		DOMAIN,
		SOURCES
	]
	_sort_by = (HOST,)

	def __str__(self):
		return self.host

	def __repr__(self):
		white = Fore.WHITE
		magenta = Fore.MAGENTA
		reset = Style.RESET_ALL
		sources_str = ', '.join([f'{magenta}{source}{reset}' for source in self.sources])
		return f'{white}{self.host} [{sources_str}]'
