import os
import csv
import yaml

from secsy.definitions import GOOGLE_CREDENTIALS_PATH, GOOGLE_DRIVE_PARENT_FOLDER_ID
from secsy.exporters._base import Exporter
from secsy.rich import console
from secsy.utils import pluralize


class GoogleSheetsExporter(Exporter):
	def send(self):
		import gspread
		info = self.report.data['info']
		title = self.report.data['info']['title']
		sheet_title = f'{self.report.data["info"]["title"]}_{self.report.timestamp}'
		results = self.report.data['results']
		if not GOOGLE_CREDENTIALS_PATH:
			console.print(':file_cabinet: Missing GOOGLE_CREDENTIALS_PATH to save to Google Sheets', style='red')
			return
		if not GOOGLE_DRIVE_PARENT_FOLDER_ID:
			console.print(':file_cabinet: Missing GOOGLE_DRIVE_PARENT_FOLDER_ID to save to Google Sheets.', style='red')
			return
		client = gspread.service_account(GOOGLE_CREDENTIALS_PATH)
		sheet = client.create(title, folder_id=GOOGLE_DRIVE_PARENT_FOLDER_ID)

		# Add options worksheet for input data
		info = self.report.data['info']
		info['targets'] = '\n'.join(info['targets'])
		info['opts'] = yaml.dump(info['opts'])
		keys = [k.replace('_', ' ').upper() for k in list(info.keys())]
		ws = sheet.add_worksheet('OPTIONS', rows=2, cols=len(keys))
		sheet.values_update(
			ws.title,
			params={'valueInputOption': 'USER_ENTERED'},
			body={'values': [keys, list(info.values())]}
		)

		# Add one worksheet per output type
		for output_type, items in results.items():
			if not items:
				continue
			keys = [
				k.replace('_', ' ').upper()
				for k in list(items[0].keys())
			]
			csv_path = f'{self.report.output_folder}/{title}_{output_type}_{self.report.timestamp}.csv'
			if not os.path.exists(csv_path):
				console.print(
					f'Unable to find CSV at {csv_path}. For Google sheets reports, please enable CSV reports as well.')
				return
			sheet_title = pluralize(output_type).upper()
			ws = sheet.add_worksheet(sheet_title, rows=len(items), cols=len(keys))
			with open(csv_path, 'r') as f:
				data = csv.reader(f)
				data = list(data)
				data[0] = [
					k.replace('_', ' ').upper()
					for k in data[0]
				]
				sheet.values_update(
					ws.title,
					params={'valueInputOption': 'USER_ENTERED'},
					body={'values': data}
				)

		# Delete 'default' worksheet
		ws = sheet.get_worksheet(0)
		sheet.del_worksheet(ws)

		console.log(f':file_cabinet: Saved Google Sheets reports to [u magenta]{sheet.url}[/]')