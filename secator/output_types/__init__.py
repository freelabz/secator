__all__ = [
	'Ai',
	'Domain',
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
	'Technology',
	'Url',
	'UserAccount',
	'Vulnerability',
	'Warning',
]
from secator.output_types._base import OutputType
from secator.output_types.ai import Ai
from secator.output_types.progress import Progress
from secator.output_types.ip import Ip
from secator.output_types.exploit import Exploit
from secator.output_types.port import Port
from secator.output_types.subdomain import Subdomain
from secator.output_types.tag import Tag
from secator.output_types.target import Target
from secator.output_types.technology import Technology
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
from secator.output_types.domain import Domain


EXECUTION_TYPES = [
	Target, Progress, Info, Warning, Error, State
]  # fmt: off
STAT_TYPES = [
	Stat
]  # fmt: off
FINDING_TYPES = [
	Subdomain, Ip, Port, Url, Tag, Exploit, UserAccount, Vulnerability, Certificate, Record, Domain, Ai, Technology
]  # fmt: off
OUTPUT_TYPES = FINDING_TYPES + EXECUTION_TYPES + STAT_TYPES
INTERNAL_FIELDS = ('_context', '_uuid', '_related', '_duplicate')

_OUTPUT_TYPE_NAMES = {t.get_name() for t in OUTPUT_TYPES}


def is_output_type(item):
	"""True if ``item`` is an OutputType instance.

	Compares by ``_type`` name rather than ``type(item) in OUTPUT_TYPES``: class identity is not stable
	across a module reload (the test harness' ``clear_modules()`` and ``secator worker -r`` autoreload
	both produce two live generations of the output-type classes), which would make an identity check
	silently reject a valid finding. The ``_type`` name is a stable string.
	"""
	name = getattr(item, '_type', None)
	return name is not None and name in _OUTPUT_TYPE_NAMES
