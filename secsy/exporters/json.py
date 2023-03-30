import json

from secsy.exporters._base import Exporter
from secsy.rich import console


class JSONExporter(Exporter):
	def send(self):
		title = self.report.data['info']['title']
		json_path = f'{self.report.output_folder}/{title}_{self.report.timestamp}.json'

		# Save JSON report to file
		with open(json_path, 'w') as f:
			json.dump(self.report.data, f, indent=2)
		
		console.log(f':file_cabinet: Saved JSON report to {json_path}')