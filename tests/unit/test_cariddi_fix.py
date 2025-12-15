"""Test for cariddi UnboundLocalError fix."""
import unittest
from unittest.mock import Mock

from secator.tasks.cariddi import cariddi


class TestCariddiFix(unittest.TestCase):
    """Test cariddi handles errors/secrets without params."""

    def test_errors_without_params(self):
        """Test that errors can be processed without params being present."""
        # Mock self
        mock_self = Mock()
        mock_self.get_opt_value = Mock(return_value=None)
        
        # Test data: errors without params
        item = {
            "url": "http://testphp.vulnweb.com/",
            "method": "GET",
            "status_code": 200,
            "words": 100,
            "lines": 10,
            "content_type": "text/html",
            "matches": {
                "errors": [
                    {"name": "MySQL error", "match": "You have an error in your SQL syntax"}
                ]
            }
        }
        
        # Should not raise UnboundLocalError
        results = list(cariddi.on_json_loaded(mock_self, item))
        
        # Should have at least 2 results: 1 Url + 1 Tag (error)
        self.assertGreaterEqual(len(results), 2)
        
        # Check that error tag was created
        error_tags = [r for r in results if hasattr(r, 'category') and r.category == 'error']
        self.assertEqual(len(error_tags), 1)
        self.assertEqual(error_tags[0].name, 'mysql_error')
        self.assertEqual(error_tags[0].match, 'http://testphp.vulnweb.com/')
        
    def test_secrets_without_params(self):
        """Test that secrets can be processed without params being present."""
        # Mock self
        mock_self = Mock()
        mock_self.get_opt_value = Mock(return_value=None)
        
        # Test data: secrets without params
        item = {
            "url": "http://testphp.vulnweb.com/",
            "method": "GET",
            "status_code": 200,
            "words": 100,
            "lines": 10,
            "content_type": "text/html",
            "matches": {
                "secrets": [
                    {"name": "API key", "match": "sk_test_1234567890"}
                ]
            }
        }
        
        # Should not raise UnboundLocalError
        results = list(cariddi.on_json_loaded(mock_self, item))
        
        # Should have at least 2 results: 1 Url + 1 Tag (secret)
        self.assertGreaterEqual(len(results), 2)
        
        # Check that secret tag was created
        secret_tags = [r for r in results if hasattr(r, 'category') and r.category == 'secret']
        self.assertEqual(len(secret_tags), 1)
        self.assertEqual(secret_tags[0].name, 'api_key')
        self.assertEqual(secret_tags[0].match, 'http://testphp.vulnweb.com/')
        
    def test_combined_without_params(self):
        """Test that both errors and secrets can be processed without params."""
        # Mock self
        mock_self = Mock()
        mock_self.get_opt_value = Mock(return_value=None)
        
        # Test data: both errors and secrets without params
        item = {
            "url": "http://testphp.vulnweb.com/",
            "method": "GET",
            "status_code": 200,
            "words": 100,
            "lines": 10,
            "content_type": "text/html",
            "matches": {
                "errors": [
                    {"name": "MySQL error", "match": "You have an error in your SQL syntax"}
                ],
                "secrets": [
                    {"name": "API key", "match": "sk_test_1234567890"}
                ]
            }
        }
        
        # Should not raise UnboundLocalError
        results = list(cariddi.on_json_loaded(mock_self, item))
        
        # Should have at least 3 results: 1 Url + 1 Tag (error) + 1 Tag (secret)
        self.assertGreaterEqual(len(results), 3)
        
        # Check that both error and secret tags were created
        error_tags = [r for r in results if hasattr(r, 'category') and r.category == 'error']
        secret_tags = [r for r in results if hasattr(r, 'category') and r.category == 'secret']
        self.assertEqual(len(error_tags), 1)
        self.assertEqual(len(secret_tags), 1)


if __name__ == '__main__':
    unittest.main()
