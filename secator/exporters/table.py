from rich.markdown import Markdown

from secator.exporters._base import Exporter
from secator.output_types import OUTPUT_TYPES, OutputType
from secator.rich import build_table, console
from secator.utils import pluralize


class TableExporter(Exporter):
	_type_map = {cls.get_name(): cls for cls in OUTPUT_TYPES}

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
				cast_items = []
				for item in items:
					if isinstance(item, dict):
						cls = self._type_map.get(item.get('_type'))
						if cls:
							try:
								item = cls.load(item)
							except TypeError as e:
								_type = item.get('_type')
								console.print(f'[bold orange1]Warning:[/] TableExporter could not cast item of type {_type!r}: {e}. Skipping.')
								continue
					cast_items.append(item)
				if not cast_items:
					continue
				items = cast_items
				is_output_type = all(isinstance(item, OutputType) for item in items)
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
