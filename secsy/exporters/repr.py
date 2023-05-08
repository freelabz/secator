from secsy.exporters._base import Exporter
from secsy.rich import console


class ReprExporter(Exporter):
	def send(self):
		results = self.report.data['results']

		# Save JSON report to file
		for output_type, items in results.items():
			console.print(output_type.upper(), style='bold gold3', justify='left')
			for item in items:
				print(repr(item))
			print('')
