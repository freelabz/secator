import os
import csv
import yaml

from secator.definitions import GOOGLE_CREDENTIALS_PATH, GOOGLE_DRIVE_PARENT_FOLDER_ID
from secator.exporters._base import Exporter
from secator.rich import console
from secator.utils import pluralize


class GdriveExporter(Exporter):
	def send(self):
		import gspread
		ws = self.report.workspace_name
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

		# Create workspace folder if it doesn't exist
		folder_id = self.get_folder_by_name(ws, parent_id=GOOGLE_DRIVE_PARENT_FOLDER_ID)
		if ws and not folder_id:
			folder_id = self.create_folder(
				folder_name=ws,
				parent_id=GOOGLE_DRIVE_PARENT_FOLDER_ID)

		# Create worksheet
		sheet = client.create(title, folder_id=folder_id)

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
			items = [i.toDict() for i in items]
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

		console.print(f':file_cabinet: Saved Google Sheets reports to [u magenta]{sheet.url}[/]')

	def create_folder(self, folder_name, parent_id=None):
		from googleapiclient.discovery import build
		from google.oauth2 import service_account
		creds = service_account.Credentials.from_service_account_file(GOOGLE_CREDENTIALS_PATH)
		service = build('drive', 'v3', credentials=creds)
		body = {
			'name': folder_name,
			'mimeType': "application/vnd.google-apps.folder"
		}
		if parent_id:
			body['parents'] = [parent_id]
		folder = service.files().create(body=body, fields='id').execute()
		return folder['id']

	def list_folders(self, parent_id):
		from googleapiclient.discovery import build
		from google.oauth2 import service_account
		creds = service_account.Credentials.from_service_account_file(GOOGLE_CREDENTIALS_PATH)
		service = build('drive', 'v3', credentials=creds)
		driveid = service.files().get(fileId='root').execute()['id']
		response = service.files().list(
			q=f"'{parent_id}' in parents and mimeType='application/vnd.google-apps.folder'",
			driveId=driveid,
			corpora='drive',
			includeItemsFromAllDrives=True,
			supportsAllDrives=True
		).execute()
		return response

	def get_folder_by_name(self, name, parent_id=None):
		response = self.list_folders(parent_id=parent_id)
		existing = [i for i in response['files'] if i['name'] == name]
		if existing:
			return existing[0]['id']
		return None
