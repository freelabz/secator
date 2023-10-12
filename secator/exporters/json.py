from secator.exporters._base import Exporter
from secator.rich import console
from secator.serializers.dataclass import dumps_dataclass


class JsonExporter(Exporter):
	def send(self):
		title = self.report.data['info']['title']
		json_path = f'{self.report.output_folder}/{title}_{self.report.timestamp}.json'

		# Save JSON report to file
		with open(json_path, 'w') as f:
			f.write(dumps_dataclass(self.report.data, indent=2))

		console.print(f':file_cabinet: Saved JSON report to {json_path}')
