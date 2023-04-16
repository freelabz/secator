from dataclasses import dataclass, field

from secsy.output_types import OutputType


@dataclass
class Progress(OutputType):
	duration: str
	percent: int
	errors: list = field(default_factory=list)
	extra_data: dict = field(default_factory=dict)
	_source: str = field(default='', repr=True)
	_type: str = field(default='metric', repr=True)
	_uuid: str = field(default='', repr=True, compare=False)

	_table_fields = ['percent', 'duration']
	_sort_by = ('percent',)

	def __str__(self) -> str:
		return f'{self.percent}%'
