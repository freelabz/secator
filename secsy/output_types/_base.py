import inspect
import re
from dataclasses import dataclass, fields, field, asdict
from secsy.rich import console

import logging

logger = logging.getLogger(__name__)


@dataclass
class OutputType:
	_table_fields = []
	_sort_by = ()

	@classmethod
	def load(cls, item, output_map):
		new_item = {}
		new_item['_type'] = cls.get_name()
		if not output_map:
			return cls(**item)
		for key in output_map:
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
		return cls(**new_item)
	
	@classmethod
	def get_fields(cls):
		attrs = inspect.getmembers(cls, lambda a:not(inspect.isroutine(a)))
		return [
			a for a in attrs if not(a[0].startswith('__') and a[0].endswith('__'))
		]

	@classmethod
	def get_name(cls):
		return re.sub(r'(?<!^)(?=[A-Z])', '_', cls.__name__).lower()
	
	@classmethod
	def keys(cls):
		return [f.name for f in fields(cls)]

	def toDict(self):
		return {k: str(v) for k, v in asdict(self).items()}