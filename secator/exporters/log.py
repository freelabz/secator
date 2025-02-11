from secator.exporters._base import Exporter
from secator.output_types import Info
from secator.rich import console


class LogExporter(Exporter):
	def send(self):
		output = self.report.runner.output
		log_path = f'{self.report.output_folder}/log.txt'
		with open(log_path, 'w') as f:
			f.write(output)

		info = Info(f'Saved run logs to {log_path}')
		console.print(info)
