from dataclasses import dataclass, field
from typing import List

from secsy.definitions import DOMAIN, HOST, SOURCES
from secsy.output_types import OutputType


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
