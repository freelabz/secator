import csv as _csv

from secator.exporters._base import Exporter
from secator.rich import console


class CsvExporter(Exporter):
    def send(self):
        results = self.report.data['results']
        csv_paths = []

        for output_type, items in results.items():
            items = [i.toDict() for i in items]
            if not items:
                continue
            keys = list(items[0].keys())
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

        console.print(f':file_cabinet: Saved CSV reports to {csv_paths_str}')
