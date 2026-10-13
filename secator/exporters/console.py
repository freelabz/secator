from rich.markdown import Markdown
from rich.markup import escape

from secator.exporters._base import Exporter
from secator.output_types import OUTPUT_TYPES
from secator.rich import console_stdout

# Extra vulnerability fields revealed by --show-all, in display order.
_VULN_SHOW_ALL_FIELDS = ["epss_score", "description", "remediation", "impact", "poc"]


def _is_markdown(text):
	"""Return True if any line in text starts with '#', indicating Markdown content."""
	return any(line.startswith("#") for line in text.splitlines())


def _print_vuln_extra(item):
	"""Print non-empty extra vulnerability fields (epss_score, description, remediation, impact, poc)."""
	for field_name in _VULN_SHOW_ALL_FIELDS:
		value = getattr(item, field_name, None)
		if value is None or value == "" or value == 0.0:
			continue
		label = " ".join(field_name.split("_")).title()
		if isinstance(value, str) and len(value) > 200:
			value = value[:200] + "…"
		# Escape the value so finding content with stray Rich tags renders literally
		# (and can't raise MarkupError); the label styling is preserved.
		console_stdout.print(f"  [dim cyan]{label}:[/] {escape(str(value))}", highlight=False)


class ConsoleExporter(Exporter):
	# Map type names to classes for fast lookup
	_type_map = {cls.get_name(): cls for cls in OUTPUT_TYPES}

	def send(self):
		results = self.report.data["results"]
		show_all = getattr(self.report, "show_all", False)
		for items in results.values():
			for item in items:
				if isinstance(item, str):
					if _is_markdown(item):
						console_stdout.print(Markdown(item))
					else:
						console_stdout.print(item, markup=False, highlight=False)
				else:
					if isinstance(item, dict):
						cls = self._type_map.get(item.get("_type"))
						if cls:
							try:
								item = cls.load(item)
							except (TypeError, Exception):
								pass
					# Grouped findings carry a _group_count; show it next to the line.
					count = getattr(item, "_group_count", 0)
					if count:
						console_stdout.print(item, f"[dim](count: {count})[/]", highlight=False)
					else:
						console_stdout.print(item, highlight=False)
					# --show-all: print extra vulnerability fields below the main line.
					if show_all and getattr(item, "_type", None) == "vulnerability":
						_print_vuln_extra(item)
