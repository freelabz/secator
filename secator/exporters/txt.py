from secator.exporters._base import Exporter
from secator.output_types import OUTPUT_TYPES, Info
from secator.rich import console


class TxtExporter(Exporter):
	_type_map = {cls.get_name(): cls for cls in OUTPUT_TYPES}

	def send(self):
		results = self.report.data['results']
		if not results:
			return
		txt_paths = []

		for output_type, items in results.items():
			if not items:
				continue
			txt_path = f'{self.report.output_folder}/report_{output_type}.txt'
			with open(txt_path, 'w') as f:
				first = True
				for item in items:
					if isinstance(item, dict):
						cls = self._type_map.get(item.get('_type'))
						if cls:
							try:
								item = cls.load(item)
							except TypeError:
								pass
					if not first:
						f.write('\n')
					f.write(str(item))
					first = False
			txt_paths.append(txt_path)

		if not txt_paths:
			return

		if len(txt_paths) == 1:
			txt_paths_str = txt_paths[0]
		else:
			txt_paths_str = '\n   • ' + '\n   • '.join(txt_paths)

		info = Info(f'Saved TXT reports to {txt_paths_str}')
		console.print(info)
