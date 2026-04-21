from secator.exporters._base import Exporter
from secator.output_types import Info
from secator.rich import console
from secator.serializers.dataclass import dump_dataclass


class JsonExporter(Exporter):
	def send(self):
		json_path = f'{self.report.output_folder}/report.json'

		# Stream JSON directly to file to avoid building full string in memory
		with open(json_path, 'w') as f:
			dump_dataclass(self.report.data, f, indent=2)

		info = Info(f'Saved JSON report to {json_path}')
		console.print(info)
