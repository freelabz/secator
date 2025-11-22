"""Unit tests for File output type."""
import time
from secator.output_types import File


def test_file_creation():
	"""Test basic File output type creation."""
	f = File(
		path='/tmp/test.txt',
		type='local',
		category='download',
		tags=['web', 'js'],
		size=1024,
		mime_type='text/plain',
		hash='abc123def456'
	)

	assert f.path == '/tmp/test.txt'
	assert f.type == 'local'
	assert f.category == 'download'
	assert f.tags == ['web', 'js']
	assert f.size == 1024
	assert f.mime_type == 'text/plain'
	assert f.hash == 'abc123def456'
	assert f._type == 'file'


def test_file_defaults():
	"""Test File output type with default values."""
	f = File(path='/tmp/test.txt')

	assert f.path == '/tmp/test.txt'
	assert f.type == 'local'  # Default type
	assert f.category == 'general'
	assert f.tags == []
	assert f.size == 0
	assert f.mime_type == ''
	assert f.hash == ''
	assert f.extra_data == {}


def test_file_str_repr():
	"""Test File string representations."""
	f = File(
		path='/tmp/test.txt',
		category='download',
		tags=['web'],
		size=2048
	)

	assert str(f) == '/tmp/test.txt'
	assert '/tmp/test.txt' in repr(f)
	assert 'download' in repr(f)


def test_file_with_related():
	"""Test File with related output types."""
	f = File(
		path='/tmp/response.html',
		category='http',
		tags=['response'],
		_related=['url_123', 'vuln_456']
	)

	assert f.path == '/tmp/response.html'
	assert len(f._related) == 2
	assert 'url_123' in f._related


def test_file_timestamp():
	"""Test File has timestamp."""
	before = time.time()
	f = File(path='/tmp/test.txt')
	after = time.time()

	assert before <= f._timestamp <= after


def test_file_get_name():
	"""Test File class name conversion."""
	assert File.get_name() == 'file'


def test_file_table_fields():
	"""Test File has proper table fields."""
	assert 'path' in File._table_fields
	assert 'type' in File._table_fields
	assert 'category' in File._table_fields
	assert 'tags' in File._table_fields
	assert 'size' in File._table_fields


def test_file_comparison():
	"""Test File equality comparison."""
	f1 = File(path='/tmp/test.txt', category='download')
	f2 = File(path='/tmp/test.txt', category='download')
	f3 = File(path='/tmp/other.txt', category='download')

	assert f1 == f2
	assert f1 != f3


def test_file_to_dict():
	"""Test File conversion to dictionary."""
	f = File(
		path='/tmp/test.txt',
		type='gcs',
		category='download',
		size=512,
		mime_type='text/plain'
	)

	data = f.toDict()
	assert data['path'] == '/tmp/test.txt'
	assert data['type'] == 'gcs'
	assert data['category'] == 'download'
	assert data['size'] == 512
	assert data['_type'] == 'file'


def test_file_type_gcs():
	"""Test File with GCS type."""
	f = File(
		path='gs://my-bucket/data.txt',
		type='gcs',
		category='export'
	)

	assert f.type == 'gcs'
	assert f.path.startswith('gs://')
	# GCS files should use cloud icon in repr
	assert '☁️' in repr(f) or 'gcs' in repr(f)
