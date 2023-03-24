from secsy.output_types import OutputType
from dataclasses import dataclass, field

from secsy.definitions import *

from typing import List


@dataclass
class Subdomain(OutputType):
	host: str
	domain: str
	sources: List[str] = field(default_factory=list)
	_source: str = field(default='', repr=True)
	_type: str = field(default='', repr=True)

	_output_field = HOST
	_sort_by = (HOST,)