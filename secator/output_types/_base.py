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

	def merge_with(self, data: 'OutputType', exclude_fields=[]):
		"""Enrich the OutputType object with the data from another object."""
		for k, v in data.toDict(exclude_fields).items():
			if v is None or v == '' or v == []:
				continue
			if isinstance(v, list):
				existing = getattr(self, k, [])
				new = [_ for _ in v if _ not in existing]
				setattr(self, k, existing + new)
			elif isinstance(v, dict):
				setattr(self, k, {**getattr(self, k), **v})
			else:
				setattr(self, k, v)

	def __str__(self):
		return self.__class__.__name__

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

	@classmethod
	def validate_fields(cls, data: dict) -> list:
		"""Validate data types against dataclass field definitions.

		Returns a list of error messages for invalid fields.
		"""
		errors = []
		type_names = {str: 'str', int: 'int', float: 'float', dict: 'dict', list: 'list', bool: 'bool'}
		for f in fields(cls):
			if f.name.startswith('_') or f.name not in data:
				continue
			value = data[f.name]
			if value is None:
				continue
			expected_type = f.type if isinstance(f.type, type) else None
			if expected_type is None:
				origin = getattr(f.type, '__origin__', None)
				if origin is not None:
					expected_type = origin
			if expected_type and not isinstance(value, expected_type):
				expected_name = type_names.get(expected_type, getattr(expected_type, '__name__', str(expected_type)))
				actual_name = type_names.get(type(value), type(value).__name__)
				errors.append(f"'{f.name}' expected {expected_name}, got {actual_name}: {repr(value)[:100]}")
		return errors

	@classmethod
	def schema(cls) -> str:
		"""Get a human-readable schema string for this OutputType class."""
		lines = [f"{cls.__name__}("]
		type_names = {str: 'str', int: 'int', float: 'float', dict: 'dict', list: 'list', bool: 'bool'}
		for f in fields(cls):
			if f.name.startswith('_'):
				continue
			type_name = type_names.get(f.type, str(f.type)) if isinstance(f.type, type) else str(f.type)
			if not isinstance(f.default, _MISSING_TYPE):
				lines.append(f"  {f.name}: {type_name} = {repr(f.default)},")
			elif not isinstance(f.default_factory, _MISSING_TYPE):
				lines.append(f"  {f.name}: {type_name} = {repr(f.default_factory())},")
			else:
				lines.append(f"  {f.name}: {type_name},  # required")
		lines.append(")")
		return "\n".join(lines)
