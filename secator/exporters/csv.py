import csv as _csv

from dataclasses import fields

from secator.exporters._base import Exporter
from secator.rich import console
from secator.output_types import FINDING_TYPES
from secator.output_types import Info


class CsvExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		if not results:
			return
		csv_paths = []

		for output_type, items in results.items():
			output_cls = [o for o in FINDING_TYPES if o._type == output_type][0]
			keys = [o.name for o in fields(output_cls)]
			items = [i.toDict() for i in items]
			if not items:
				continue
			csv_path = f'{self.report.output_folder}/report_{output_type}.csv'
			csv_paths.append(csv_path)
			with open(csv_path, 'w', newline='') as output_file:
				dict_writer = _csv.DictWriter(output_file, keys)
				dict_writer.writeheader()
				dict_writer.writerows(items)

		if len(csv_paths) == 1:
			csv_paths_str = csv_paths[0]
		else:
			csv_paths_str = '\n   • ' + '\n   • '.join(csv_paths)

		info = Info(message=f'Saved CSV reports to {csv_paths_str}')
		console.print(info)
