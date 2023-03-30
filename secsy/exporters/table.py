from secsy.exporters._base import Exporter
from secsy.utils import print_results_table


class TableExporter(Exporter):
	def send(self):
		print_results_table(self.report.runner.results, self.report.title)