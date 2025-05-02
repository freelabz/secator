__all__ = [
	'Error',
	'OutputType',
	'Info',
	'Ip',
	'Port',
	'Progress',
	'Record',
	'Stat',
	'State',
	'Subdomain',
	'Url',
	'UserAccount',
	'Vulnerability',
	'Warning',
]
from secator.output_types._base import OutputType
from secator.output_types.progress import Progress
from secator.output_types.ip import Ip
from secator.output_types.exploit import Exploit
from secator.output_types.port import Port
from secator.output_types.subdomain import Subdomain
from secator.output_types.tag import Tag
from secator.output_types.target import Target
from secator.output_types.url import Url
from secator.output_types.user_account import UserAccount
from secator.output_types.vulnerability import Vulnerability
from secator.output_types.record import Record
from secator.output_types.certificate import Certificate
from secator.output_types.info import Info
from secator.output_types.warning import Warning
from secator.output_types.error import Error
from secator.output_types.stat import Stat
from secator.output_types.state import State
from secator.utils import pluralize

EXECUTION_TYPES = [
	Target, Progress, Info, Warning, Error, State
]
STAT_TYPES = [
	Stat
]
FINDING_TYPES = [
	Subdomain, Ip, Port, Url, Tag, Exploit, UserAccount, Vulnerability, Certificate
]
OUTPUT_TYPES = FINDING_TYPES + EXECUTION_TYPES + STAT_TYPES


class OutputTypeList(list):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def __getattr__(self, name):
		output_types_singular = [_._type for _ in OUTPUT_TYPES]
		output_types_plural = [pluralize(_) for _ in output_types_singular]
		if name in output_types_plural:
			return self.filter_by_type(output_types_singular[output_types_plural.index(name)])
		elif name in output_types_singular:
			return self.filter_by_type(name)
		else:
			raise AttributeError(f'{name} is not a valid output type')

	def __str__(self):
		return '[' + ', '.join([str(_) for _ in self]) + ']'

	def filter_by_source(self, source):
		return OutputTypeList([_ for _ in self if _._source.startswith(source)])

	def filter_by_type(self, type):
		return OutputTypeList([_ for _ in self if _._type == type])

	def filter_by_types(self, types):
		return OutputTypeList([_ for _ in self if _._type in types])

	def filter_by_field(self, field, value):
		return OutputTypeList([_ for _ in self if hasattr(_, field) and getattr(_, field) == value])

	def query(self, query):
		return OutputTypeList([_ for _ in self if all(getattr(_, field) == value for field, value in query.items())])
