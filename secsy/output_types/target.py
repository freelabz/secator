from dataclasses import dataclass, field

from secsy.output_types import OutputType


@dataclass
class Target(OutputType):
	name: str
	_source: str = field(default='', repr=True)
	_type: str = field(default='target', repr=True)
	_uuid: str = field(default='', repr=True)

	_table_fields = [
		'name',
	]
	_sort_by = ('name',)

	def __str__(self):
		return self.name
