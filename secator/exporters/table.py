from secator.exporters._base import Exporter
from secator.utils import pluralize
from secator.rich import build_table, console
from rich.markdown import Markdown
from secator.output_types import OutputType


class TableExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		if not results:
			return
		title = self.report.title
		_print = console.print
		_print()
		if title:
			title = ' '.join(title.capitalize().split('_')) + ' results'
			h1 = Markdown(f'# {title}')
			_print(h1, style='bold magenta', width=50)
			_print()
		for output_type, items in results.items():
			if output_type == 'progress':
				continue
			if items:
				is_output_type = isinstance(items[0], OutputType)
				output_fields = items[0]._table_fields if is_output_type else None
				sort_by = items[0]._sort_by if is_output_type else []
				_table = build_table(
					items,
					output_fields=output_fields,
					sort_by=sort_by)
				title = pluralize(items[0]._type).upper() if is_output_type else 'Results'
				_print(f':wrench: {title}', style='bold gold3', justify='left')
				_print(_table)
				_print()
