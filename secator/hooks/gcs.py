import warnings

from pathlib import Path
from time import time

from google.cloud import storage

from secator.config import CONFIG
from secator.runners import Task
from secator.thread import Thread
from secator.utils import debug

warnings.filterwarnings("ignore", "Your application has authenticated using end user credentials")

GCS_BUCKET_NAME = CONFIG.addons.gcs.bucket_name
ITEMS_TO_SEND = {
	'url': ['screenshot_path', 'stored_response_path']
}

_gcs_client = None


def get_gcs_client():
	"""Get or create GCS client"""
	global _gcs_client
	if _gcs_client is None:
		_gcs_client = storage.Client()
	return _gcs_client


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


def upload_resume_file(self, checkpoint):
	"""Upload resume file to GCS and update checkpoint path."""
	from secator.output_types import Checkpoint
	if not isinstance(checkpoint, Checkpoint):
		return checkpoint
	if not GCS_BUCKET_NAME:
		debug('skipped since addons.gcs.bucket_name is empty.', sub='hooks.gcs')
		return checkpoint
	resume_path = checkpoint.resume_file_path
	if not resume_path or not Path(resume_path).exists():
		return checkpoint
	blob_name = f'resume/{checkpoint.task_name}_resume.cfg'
	# Upload synchronously so path is updated before Checkpoint is yielded
	upload_blob(GCS_BUCKET_NAME, resume_path, blob_name)
	checkpoint.resume_file_path = f'gs://{GCS_BUCKET_NAME}/{blob_name}'
	return checkpoint


def download_resume_file(self, item):
	"""Download GCS resume file to local reports_dir before tool runs."""
	resume_path = self.get_opt_value('resume') or ''
	if not resume_path.startswith('gs://'):
		return item
	if not GCS_BUCKET_NAME:
		return item
	parts = resume_path[5:].split('/', 1)
	if len(parts) != 2:
		return item
	bucket_name, blob_name = parts
	local_path = f'{self.reports_folder}/.outputs/{self.unique_name}_resume.cfg'
	Path(local_path).parent.mkdir(parents=True, exist_ok=True)
	download_blob(bucket_name, blob_name, local_path)
	self.run_opts['resume'] = local_path
	return item


def upload_blob(bucket_name, source_file_name, destination_blob_name):
	"""Uploads a file to the bucket."""
	start_time = time()
	storage_client = get_gcs_client()
	bucket = storage_client.bucket(bucket_name)
	blob = bucket.blob(destination_blob_name)
	with open(source_file_name, 'rb') as f:
		f.seek(0)
		blob.upload_from_file(f)
	end_time = time()
	elapsed = end_time - start_time
	debug(f'in {elapsed:.4f}s', obj={'blob': 'UPLOADED', 'blob_name': destination_blob_name, 'bucket': bucket_name}, obj_after=False, sub='hooks.gcs')  # noqa: E501


def download_blob(bucket_name, source_blob_name, destination_file_name):
	"""Downloads a file from the bucket."""
	start_time = time()
	storage_client = get_gcs_client()
	bucket = storage_client.bucket(bucket_name)
	blob = bucket.blob(source_blob_name)
	blob.download_to_filename(destination_file_name)
	end_time = time()
	elapsed = end_time - start_time
	debug(f'in {elapsed:.4f}s', obj={'blob': 'DOWNLOADED', 'blob_name': source_blob_name, 'bucket': bucket_name}, obj_after=False, sub='hooks.gcs')  # noqa: E501


HOOKS = {
	Task: {
		'on_item': [process_item],
		'on_cmd_interrupt': [upload_resume_file],
		'on_cmd': [download_resume_file],
	}
}
