import warnings

from pathlib import Path
from time import time

from secator.config import CONFIG
from secator.drivers._base import Driver
from secator.thread import Thread
from secator.utils import debug

warnings.filterwarnings("ignore", "Your application has authenticated using end user credentials")

ITEMS_TO_SEND = {
	'url': ['screenshot_path', 'stored_response_path']
}

_gcs_client = None


def get_gcs_client():
	"""Get or create GCS client (module-level singleton, not pickled with driver instances)."""
	global _gcs_client
	if _gcs_client is None:
		from google.cloud import storage
		_gcs_client = storage.Client()
	return _gcs_client


class GCSDriver(Driver):
	"""Google Cloud Storage driver. Uploads item file attachments to a GCS bucket."""

	def __init__(self, bucket_name=None):
		self.bucket_name = bucket_name or CONFIG.addons.gcs.bucket_name

	@property
	def hooks(self):
		from secator.runners import Task
		return {
			Task: {'on_item': [self.on_item]}
		}

	def check(self) -> bool:
		return bool(self.bucket_name)

	def on_item(self, runner, item):
		if item._type not in ITEMS_TO_SEND:
			return item
		if not self.bucket_name:
			debug('skipped since bucket_name is empty.', sub='drivers.gcs')
			return item
		to_send = ITEMS_TO_SEND[item._type]
		for k, v in item.toDict().items():
			if k in to_send and v:
				path = Path(v)
				if not path.exists():
					continue
				ext = path.suffix
				blob_name = f'{item._uuid}_{k}{ext}'
				t = Thread(target=self.upload_blob, args=(self.bucket_name, v, blob_name))
				t.start()
				runner.threads.append(t)
				setattr(item, k, f'gs://{self.bucket_name}/{blob_name}')
		return item

	def upload_blob(self, bucket_name, source_file_name, destination_blob_name):
		"""Upload a file to the GCS bucket."""
		start_time = time()
		storage_client = get_gcs_client()
		bucket = storage_client.bucket(bucket_name)
		blob = bucket.blob(destination_blob_name)
		with open(source_file_name, 'rb') as f:
			f.seek(0)
			blob.upload_from_file(f)
		elapsed = time() - start_time
		debug(f'in {elapsed:.4f}s', obj={'blob': 'UPLOADED', 'blob_name': destination_blob_name, 'bucket': bucket_name}, obj_after=False, sub='drivers.gcs')  # noqa: E501

	def download_blob(self, bucket_name, source_blob_name, destination_file_name):
		"""Download a file from the GCS bucket."""
		start_time = time()
		storage_client = get_gcs_client()
		bucket = storage_client.bucket(bucket_name)
		blob = bucket.blob(source_blob_name)
		blob.download_to_filename(destination_file_name)
		elapsed = time() - start_time
		debug(f'in {elapsed:.4f}s', obj={'blob': 'DOWNLOADED', 'blob_name': source_blob_name, 'bucket': bucket_name}, obj_after=False, sub='drivers.gcs')  # noqa: E501
