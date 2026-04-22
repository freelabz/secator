import unittest
from unittest import mock
from click.shell_completion import CompletionItem

from secator.completion import (
	complete_profiles,
	complete_workspaces,
	complete_drivers,
	complete_exporters
)


class TestCompletion(unittest.TestCase):

	def test_complete_profiles(self):
		"""Test profile name completion."""
		with mock.patch('secator.completion.get_configs_by_type') as mock_get_configs:
			# Mock profile configs
			mock_profile1 = mock.MagicMock()
			mock_profile1.name = 'active'
			mock_profile2 = mock.MagicMock()
			mock_profile2.name = 'aggressive'
			mock_profile3 = mock.MagicMock()
			mock_profile3.name = 'passive'
			mock_get_configs.return_value = [mock_profile1, mock_profile2, mock_profile3]
			
			# Test completion with prefix
			results = complete_profiles(None, None, 'ag')
			result_names = [item.value for item in results]
			assert 'aggressive' in result_names
			assert 'active' not in result_names
			
			# Test completion with empty prefix
			results = complete_profiles(None, None, '')
			result_names = [item.value for item in results]
			assert len(result_names) == 3
			assert 'active' in result_names
			assert 'aggressive' in result_names
			assert 'passive' in result_names

	def test_complete_workspaces(self):
		"""Test workspace name completion."""
		with mock.patch('os.walk') as mock_walk:
			# Mock workspace directories - need to return a fresh iterator each time
			def mock_walk_func(*args):
				return iter([('root', ['default', 'test', 'prod'], [])])
			mock_walk.side_effect = mock_walk_func
			
			# Test completion with prefix
			results = complete_workspaces(None, None, 'te')
			result_names = [item.value for item in results]
			assert 'test' in result_names
			assert 'default' not in result_names
			
			# Test completion with empty prefix
			results = complete_workspaces(None, None, '')
			result_names = [item.value for item in results]
			assert len(result_names) == 3

	def test_complete_drivers(self):
		"""Test driver name completion."""
		# Test completion with prefix
		results = complete_drivers(None, None, 'mo')
		result_names = [item.value for item in results]
		assert 'mongodb' in result_names
		assert 'gcs' not in result_names
		
		# Test completion with empty prefix
		results = complete_drivers(None, None, '')
		result_names = [item.value for item in results]
		assert 'mongodb' in result_names
		assert 'gcs' in result_names
		assert len(result_names) >= 2  # At least these two drivers

	def test_complete_exporters(self):
		"""Test exporter name completion."""
		# Test completion with prefix
		results = complete_exporters(None, None, 'js')
		result_names = [item.value for item in results]
		assert 'json' in result_names
		assert 'csv' not in result_names
		
		# Test completion with empty prefix
		results = complete_exporters(None, None, '')
		result_names = [item.value for item in results]
		assert 'csv' in result_names
		assert 'json' in result_names
		assert 'table' in result_names
		assert len(result_names) >= 3  # At least these exporters

	def test_complete_workspaces_no_directory(self):
		"""Test workspace completion when directory doesn't exist."""
		with mock.patch('os.walk', side_effect=OSError()):
			results = complete_workspaces(None, None, '')
			assert len(results) == 0


if __name__ == '__main__':
	unittest.main()
