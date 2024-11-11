import logging
import re
from dataclasses import _MISSING_TYPE, dataclass, fields
from secator.definitions import DEBUG
from secator.rich import console

logger = logging.getLogger(__name__)


@dataclass
class OutputType:
	_table_fields = []
	_sort_by = ()

	def __gt__(self, other):
		if not self.__eq__(other):
			return False

		# Point-based system based on number of non-empty extra-data present.
		# In this configuration, a > b if a == b AND a has more non-empty fields than b
		# extra_fields = [f for f in fields(self) if not f.compare]
		# points1 = 0
		# points2 = 0
		# for field in extra_fields:
		# 	v1 = getattr(self, field.name)
		# 	v2 = getattr(other, field.name)
		# 	if v1 and not v2:
		# 		points1 += 1
		# 	elif v2 and not v1:
		# 		points2 += 1
		# if points1 > points2:
		# 	return True

		# Timestamp-based system: return newest object
		return self._timestamp > other._timestamp

	def __ge__(self, other):
		return self == other

	def __lt__(self, other):
		return other > self

	def __le__(self, other):
		return self == other

	def __post_init__(self):
		"""Initialize default fields to their proper types."""
		for field in fields(self):
			default_factory = field.default_factory
			default = field.default
			if getattr(self, field.name) is None:
				if not isinstance(default, _MISSING_TYPE):
					setattr(self, field.name, field.default)
				elif not isinstance(default_factory, _MISSING_TYPE):
					setattr(self, field.name, default_factory())

	@classmethod
	def load(cls, item, output_map={}):
		new_item = {}

		# Check for explicit _type keys
		_type = item.get('_type')
		if _type and _type != cls.get_name():
			raise TypeError(f'Item has different _type set: {_type}')

		for field in fields(cls):
			key = field.name
			if key in output_map:
				mapped_key = output_map[key]
				if callable(mapped_key):
					try:
						mapped_val = mapped_key(item)
					except Exception as e:
						mapped_val = None
						if DEBUG > 1:
							console.print_exception(show_locals=True)
						raise TypeError(
							f'Fail to transform value for "{key}" using output_map function. Exception: '
							f'{type(e).__name__}: {str(e)}')
				else:
					mapped_val = item.get(mapped_key)
				new_item[key] = mapped_val
			elif key in item:
				new_item[key] = item[key]

		# All values None, raise an error
		if all(val is None for val in new_item.values()):
			raise TypeError(f'Item does not match {cls} schema')

		new_item['_type'] = cls.get_name()
		return cls(**new_item)

	@classmethod
	def get_name(cls):
		return re.sub(r'(?<!^)(?=[A-Z])', '_', cls.__name__).lower()

	@classmethod
	def keys(cls):
		return [f.name for f in fields(cls)]

	def toDict(self, exclude=[]):
		data = self.__dict__.copy()
		if exclude:
			return {k: v for k, v in data.items() if k not in exclude}
		return data
