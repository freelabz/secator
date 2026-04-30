from rich.markdown import Markdown

from secator.exporters._base import Exporter
from secator.output_types import OUTPUT_TYPES
from secator.rich import console_stdout


def _is_markdown(text):
	"""Return True if any line in text starts with '#', indicating Markdown content."""
	return any(line.startswith('#') for line in text.splitlines())


class ConsoleExporter(Exporter):
	# Map type names to classes for fast lookup
	_type_map = {cls.get_name(): cls for cls in OUTPUT_TYPES}

	def send(self):
		results = self.report.data['results']
		for items in results.values():
			for item in items:
				if isinstance(item, str):
					if _is_markdown(item):
						console_stdout.print(Markdown(item))
					else:
						console_stdout.print(item)
				else:
					if isinstance(item, dict):
						cls = self._type_map.get(item.get('_type'))
						if cls:
							try:
								item = cls.load(item)
							except (TypeError, Exception):
								pass
					console_stdout.print(item, highlight=False)
