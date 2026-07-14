import csv as _csv

from dataclasses import fields

from secator.exporters._base import Exporter
from secator.rich import console
from secator.output_types import FINDING_TYPES
from secator.output_types.target import Target
from secator.output_types import Info


class CsvExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		if not results:
			return
		csv_paths = []
		for output_type, items in results.items():
			output_cls = next((o for o in [*FINDING_TYPES, Target] if o._type == output_type), None)
			if output_cls is None:
				continue
			if not items:  # count query on the streaming view — no materialization
				continue
			keys = [o.name for o in fields(output_cls)]
			csv_path = f'{self.report.output_folder}/report_{output_type}.csv'
			csv_paths.append(csv_path)
			with open(csv_path, 'w', newline='') as output_file:
				# extrasaction='ignore': backends (e.g. API) may attach computed fields
				# not in the output-type schema (e.g. 'is_exploitable'); only write the
				# schema columns instead of raising on extras.
				dict_writer = _csv.DictWriter(output_file, keys, extrasaction='ignore')
				dict_writer.writeheader()
				for item in items:  # stream rows from the store cursor
					dict_writer.writerow(item.toDict() if hasattr(item, 'toDict') else item)

		if not csv_paths:
			return

		if getattr(self.report.runner, 'print_reports_message', True):
			for csv_path in csv_paths:
				console.print(Info(message=f'CSV report written to {csv_path}'))
