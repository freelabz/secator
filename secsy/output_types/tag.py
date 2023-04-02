from dataclasses import dataclass, field

from secsy.output_types import OutputType


@dataclass
class Tag(OutputType):
	match: str
	extra_data: field(default_factory=dict, repr=True)
	_source: str = field(default='', repr=True)
	_type: str = field(default='ip', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = ['match']
	_sort_by = ('match',)

	def __str__(self) -> str:
		return self.match
