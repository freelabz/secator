from dataclasses import dataclass, field

from secator.output_types import OutputType


@dataclass
class Target(OutputType):
	name: str
	_source: str = field(default='', repr=True)
	_type: str = field(default='target', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)
	_context: dict = field(default_factory=dict, repr=True, compare=False)

	_table_fields = [
		'name',
	]
	_sort_by = ('name',)

	def __str__(self):
		return self.name
