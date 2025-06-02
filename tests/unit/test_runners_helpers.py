import unittest
from unittest.mock import patch

from secator.runners._helpers import (
    run_extractors,
    fmt_extractor,
    extract_from_results,
    parse_extractor,
    process_extractor,
    get_task_folder_id
)
from secator.output_types import OutputType, Url, Vulnerability, Target
from dataclasses import dataclass, field


@dataclass
class MockOutputType(OutputType):
    """Mock OutputType for testing extractors."""
    _type = 'mock'
    field1: str = field(default='value1')
    field2: int = field(default=42)
    nested: dict = field(default_factory=lambda: {'subfield': 'nested_value'})
    _context: dict = field(default_factory=dict)


class TestExtractorFunctions(unittest.TestCase):
    
    def setUp(self):
        # Create some mock objects for testing
        self.mock1 = MockOutputType(field1='test1', field2=1)
        self.mock2 = MockOutputType(field1='test2', field2=2)
        self.mock3 = MockOutputType(field1='test3', field2=3)

        self.url1 = Url(url='http://example.com')
        self.url2 = Url(url='http://example.org')

        self.target1 = Target(name='localhost')

        self.vuln1 = Vulnerability(
            name='Test Vuln', 
            description='Test Description',
            severity='high'
        )

        # Test results for extractors
        self.results = [
            self.mock1, self.mock2, self.mock3,
            self.url1, self.url2,
            self.target1,
            self.vuln1
        ]

    def test_parse_extractor_string(self):
        """Test parsing extractor from string format."""
        # Test valid string format
        result = parse_extractor('mock.field1')
        self.assertEqual(result, ('mock', 'field1', None))

        # Test invalid string format
        result = parse_extractor('invalid_format')
        self.assertIsNone(result)

        # Test empty string
        result = parse_extractor('')
        self.assertIsNone(result)

    def test_parse_extractor_dict(self):
        """Test parsing extractor from dict format."""
        # Test with all fields
        extractor = {
            'type': 'mock',
            'field': 'field1',
            'condition': 'item.field2 > 1'
        }
        result = parse_extractor(extractor)
        self.assertEqual(result, ('mock', 'field1', 'item.field2 > 1'))

        # Test with minimal fields
        extractor = {
            'type': 'mock'
        }
        result = parse_extractor(extractor)
        self.assertEqual(result, ('mock', None, None))

    def test_fmt_extractor(self):
        """Test formatting extractors for display."""
        # Test string format
        result = fmt_extractor('mock.field1')
        self.assertEqual(result, '<DYNAMIC(mock.field1)>')

        # Test dict format with condition
        extractor = {
            'type': 'mock',
            'field': 'field1',
            'condition': 'item.field2 > 1'
        }
        result = fmt_extractor(extractor)
        self.assertEqual(result, '<DYNAMIC(mock.field1 if item.field2 > 1)>')

        # Test invalid extractor
        result = fmt_extractor('invalid_format')
        self.assertEqual(result, '<DYNAMIC[INVALID_EXTRACTOR]>')

    def test_process_extractor_type_filter(self):
        """Test process_extractor filtering by type."""
        # Extract only mock types
        result = process_extractor(self.results, 'mock.field1')
        self.assertEqual(len(result), 3)
        self.assertEqual(result, ['test1', 'test2', 'test3'])

        # Extract only url types
        result = process_extractor(self.results, 'url.url')
        self.assertEqual(len(result), 2)
        self.assertEqual(result, ['http://example.com', 'http://example.org'])

    def test_process_extractor_with_condition(self):
        """Test process_extractor with conditions."""
        # Extract mock types with field2 > 1
        extractor = {
            'type': 'mock',
            'field': 'field1',
            'condition': 'item.field2 > 1'
        }
        result = process_extractor(self.results, extractor)
        self.assertEqual(len(result), 2)  # mock2 and mock3 meet condition
        self.assertEqual(result, ['test2', 'test3'])

        # Test with len function in condition
        extractor = {
            'type': 'mock',
            'field': 'field1',
            'condition': 'len(item.field1) > 3 and item.field2 == 1'
        }
        result = process_extractor(self.results, extractor, {})
        self.assertEqual(result, ['test1'])

    def test_process_extractor_with_formatted_field(self):
        """Test process_extractor with formatted fields."""
        # Test already formatted field
        extractor = {
            'type': 'mock',
            'field': '{field1}_{field2}'
        }
        result = process_extractor(self.results, extractor)
        self.assertEqual(result, ['test1_1', 'test2_2', 'test3_3'])

        # Test field that needs formatting
        extractor = {
            'type': 'mock',
            'field': 'field1'
        }
        result = process_extractor(self.results, extractor)
        self.assertEqual(result, ['test1', 'test2', 'test3'])

        # TODO: Test nested field access
        # extractor = {
        #     'type': 'mock',
        #     'field': '{nested.subfield}'
        # }
        # result = process_extractor(self.results, extractor)
        # self.assertEqual(result, ['nested_value', 'nested_value', 'nested_value'])

    def test_extract_from_results(self):
        """Test extract_from_results function."""
        # Test single extractor
        results, errors = extract_from_results(self.results, 'mock.field1')
        self.assertEqual(results, ['test1', 'test2', 'test3'])
        self.assertEqual(errors, [])

        # Test multiple extractors
        extractors = ['mock.field1', 'url.url']
        results, errors = extract_from_results(self.results, extractors)
        self.assertEqual(len(results), 5)  # 3 mock + 2 url
        self.assertEqual(errors, [])

        # Test with failing extractor
        # with patch('secator.runners._helpers.process_extractor', side_effect=Exception('Test error')):
        #     results, errors = extract_from_results(self.results, 'mock.field1')
        #     self.assertEqual(results, [])
        #     self.assertEqual(len(errors), 1)
        #     self.assertIsInstance(errors[0], Error)
        #     self.assertEqual(errors[0].message, 'Exception: Test error')

    @patch('secator.runners._helpers.deduplicate', side_effect=lambda x: x)  # Mock deduplicate to pass through
    def test_run_extractors(self, mock_deduplicate):
        """Test run_extractors function."""
        # Setup test options with extractors
        opts = {
            'targets_': ['mock.field1'],
            'other_': ['url.url']
        }

        # Test normal extraction
        inputs, updated_opts, errors = run_extractors(self.results, opts)
        self.assertEqual(inputs, ['test1', 'test2', 'test3'])
        self.assertEqual(updated_opts['other'], ['http://example.com', 'http://example.org'])
        self.assertEqual(errors, [])

        # Test dry run mode
        inputs, updated_opts, errors = run_extractors(self.results, opts, dry_run=True)
        self.assertEqual(inputs, ['<DYNAMIC(mock.field1)>'])
        self.assertEqual(updated_opts['other'], ['<DYNAMIC(url.url)>'])
        self.assertEqual(errors, [])

    @patch('os.scandir')
    @patch('os.path.exists')
    def test_get_task_folder_id(self, mock_exists, mock_scandir):
        """Test get_task_folder_id function."""
        # Test with non-existent path
        mock_exists.return_value = False
        result = get_task_folder_id('/dummy/path')
        self.assertEqual(result, 0)

        # Test with empty directory
        mock_exists.return_value = True
        mock_scandir.return_value = []
        result = get_task_folder_id('/dummy/path')
        self.assertEqual(result, 0)

        # Test with numeric directory names
        class MockDirEntry:
            def __init__(self, name, is_dir_val=True):
                self.name = name
                self._is_dir = is_dir_val

            def is_dir(self):
                return self._is_dir

        mock_exists.return_value = True
        mock_scandir.return_value = [
            MockDirEntry('1'),
            MockDirEntry('3'),
            MockDirEntry('2'),
            MockDirEntry('not_a_number'),
            MockDirEntry('5', is_dir_val=False)  # Not a directory
        ]
        result = get_task_folder_id('/dummy/path')
        self.assertEqual(result, 4)  # Max numeric dir (3) + 1


if __name__ == '__main__':
    unittest.main() 