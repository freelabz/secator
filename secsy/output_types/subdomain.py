from dataclasses import dataclass, field
from typing import List

from secsy.definitions import *
from secsy.output_types import OutputType


@dataclass
class Subdomain(OutputType):
	host: str
	domain: str
	sources: List[str] = field(default_factory=list)
	_source: str = field(default='', repr=True)
	_type: str = field(default='suybdomain', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = [
		HOST,
		DOMAIN,
		SOURCES
	]
	_sort_by = (HOST,)

	def __str__(self):
		return self.host