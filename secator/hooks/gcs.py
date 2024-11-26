from pathlib import Path
from time import time

from google.cloud import storage

from secator.config import CONFIG
from secator.runners import Task
from secator.thread import Thread
from secator.utils import debug


GCS_BUCKET_NAME = CONFIG.addons.gcs.bucket_name
ITEMS_TO_SEND = {
	'url': ['screenshot_path']
}


def process_item(self, item):
	if item._type not in ITEMS_TO_SEND.keys():
		return item
	if not GCS_BUCKET_NAME:
		debug('skipped since addons.gcs.bucket_name is empty.', sub='hooks.gcs')
		return item
	to_send = ITEMS_TO_SEND[item._type]
	for k, v in item.toDict().items():
		if k in to_send and v:
			path = Path(v)
			if not path.exists():
				continue
			ext = path.suffix
			blob_name = f'{item._uuid}_{k}{ext}'
			t = Thread(target=upload_blob, args=(GCS_BUCKET_NAME, v, blob_name))
			t.start()
			self.threads.append(t)
			setattr(item, k, f'gs://{GCS_BUCKET_NAME}/{blob_name}')
	return item


def upload_blob(bucket_name, source_file_name, destination_blob_name):
	"""Uploads a file to the bucket."""
	start_time = time()
	storage_client = storage.Client()
	bucket = storage_client.bucket(bucket_name)
	blob = bucket.blob(destination_blob_name)
	blob.upload_from_filename(source_file_name)
	end_time = time()
	elapsed = end_time - start_time
	debug(f'in {elapsed:.4f}s', obj={'blob': 'CREATED', 'blob_name': destination_blob_name, 'bucket': bucket_name}, obj_after=False, sub='hooks.gcs', verbose=True)  # noqa: E501


HOOKS = {
	Task: {'on_item': [process_item]}
}
