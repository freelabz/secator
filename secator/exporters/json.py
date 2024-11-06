from secator.exporters._base import Exporter
from secator.output_types import Info
from secator.rich import console
from secator.serializers.dataclass import dumps_dataclass


class JsonExporter(Exporter):
	def send(self):
		json_path = f'{self.report.output_folder}/report.json'

		# Save JSON report to file
		with open(json_path, 'w') as f:
			f.write(dumps_dataclass(self.report.data, indent=2))

		info = Info(f'Saved JSON report to {json_path}')
		console.print(info)
