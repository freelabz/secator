from secator.exporters._base import Exporter
from secator.output_types import Info
from secator.rich import console


class TxtExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		if not results:
			return
		txt_paths = []

		for output_type, items in results.items():
			items = [str(i) for i in items]
			if not items:
				continue
			txt_path = f'{self.report.output_folder}/report_{output_type}.txt'
			with open(txt_path, 'w') as f:
				f.write('\n'.join(items))
			txt_paths.append(txt_path)

		if len(txt_paths) == 1:
			txt_paths_str = txt_paths[0]
		else:
			txt_paths_str = '\n   • ' + '\n   • '.join(txt_paths)

		info = Info(f'Saved TXT reports to {txt_paths_str}')
		console.print(info)
