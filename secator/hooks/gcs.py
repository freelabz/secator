from secator.drivers.gcs import GCSDriver, get_gcs_client  # noqa: F401

_driver = GCSDriver()
HOOKS = _driver.hooks


def download_blob(bucket_name, source_blob_name, destination_file_name):
	"""Module-level wrapper for GCSDriver.download_blob for backward compatibility."""
	_driver.download_blob(bucket_name, source_blob_name, destination_file_name)


def upload_blob(bucket_name, source_file_name, destination_blob_name):
	"""Module-level wrapper for GCSDriver.upload_blob for backward compatibility."""
	_driver.upload_blob(bucket_name, source_file_name, destination_blob_name)
