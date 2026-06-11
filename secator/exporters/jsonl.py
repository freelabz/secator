import sys

from secator.exporters._base import Exporter
from secator.serializers.dataclass import dumps_dataclass


class JsonlExporter(Exporter):
	"""Export results as newline-delimited JSON (one object per line) to stdout.

	Useful for live streaming to jq:
	    secator r show -o jsonl | jq 'select(._type == "vulnerability")'
	"""

	def send(self):
		results = self.report.data['results']
		for items in results.values():
			for item in items:
				if hasattr(item, 'toDict'):
					d = item.toDict()
				elif isinstance(item, dict):
					d = item
				else:
					continue
				sys.stdout.write(dumps_dataclass(d) + '\n')
		sys.stdout.flush()
