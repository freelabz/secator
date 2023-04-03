import re
from dataclasses import dataclass, fields, _MISSING_TYPE

import logging

logger = logging.getLogger(__name__)


@dataclass
class OutputType:
	_table_fields = []
	_sort_by = ()

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
		for field in fields(cls):
			key = field.name
			if key in output_map:
				mapped_key = output_map[key]
				if callable(mapped_key):
					mapped_val = mapped_key(item)
				else:
					mapped_val = item.get(mapped_key)
				new_item[key] = mapped_val
			elif key in item:
				new_item[key] = item[key]
			else:
				new_item[key] = None

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

	def toDict(self):
		return self.__dict__.copy()