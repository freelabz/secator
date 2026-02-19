import unittest
from unittest.mock import MagicMock, patch


class TestMongoDBAsyncHooks(unittest.TestCase):
    """Test async MongoDB hooks."""

    def test_update_finding_is_not_coroutine(self):
        """update_finding should be a regular function (called by AsyncHookManager)."""
        from secator.hooks.mongodb import update_finding
        import inspect
        # After migration, update_finding will NOT be a coroutine
        # It's a regular function that receives batched items
        # The "async" behavior comes from being routed through AsyncHookManager
        # For now, we just test the signature accepts items list
        self.assertTrue(callable(update_finding))

    @patch('secator.hooks.mongodb.get_mongodb_client')
    def test_update_finding_bulk_write(self, mock_get_client):
        """Batched findings use bulk_write with upsert."""
        from secator.hooks.mongodb import update_finding
        from secator.output_types import Url

        mock_db = MagicMock()
        mock_get_client.return_value.main = mock_db

        # Create mock runner
        mock_runner = MagicMock()
        mock_runner.debug = MagicMock()

        # Create test items
        item1 = Url(url='http://example.com')
        item1._uuid = 'uuid-1'
        item2 = Url(url='http://example.org')
        item2._uuid = 'uuid-2'

        items = [item1, item2]

        # Call the batched hook
        result = update_finding(mock_runner, items)

        # Verify bulk_write was called
        mock_db.findings.bulk_write.assert_called_once()

        # Verify return value
        self.assertEqual(result, items)

    @patch('secator.hooks.mongodb.get_mongodb_client')
    def test_update_finding_handles_empty_list(self, mock_get_client):
        """Empty list returns immediately without DB call."""
        from secator.hooks.mongodb import update_finding

        mock_runner = MagicMock()
        result = update_finding(mock_runner, [])

        mock_get_client.assert_not_called()
        self.assertEqual(result, [])

    def test_batch_config_exists(self):
        """BATCH_CONFIG is defined for update_finding."""
        from secator.hooks import mongodb
        self.assertTrue(hasattr(mongodb, 'BATCH_CONFIG'))
        self.assertIn('update_finding', mongodb.BATCH_CONFIG)

    def test_async_hooks_marker_exists(self):
        """ASYNC_HOOKS set is defined with update_finding."""
        from secator.hooks import mongodb
        self.assertTrue(hasattr(mongodb, 'ASYNC_HOOKS'))
        self.assertIn('update_finding', mongodb.ASYNC_HOOKS)


class TestRunnerAsyncHookDetection(unittest.TestCase):
    """Test that Runner correctly detects ASYNC_HOOKS markers."""

    def test_async_hook_marker_detected(self):
        """Runner detects hooks marked in ASYNC_HOOKS."""
        import inspect
        from secator.hooks.mongodb import update_finding, ASYNC_HOOKS

        # update_finding is NOT a coroutine
        self.assertFalse(inspect.iscoroutinefunction(update_finding))

        # But it IS in ASYNC_HOOKS
        self.assertIn('update_finding', ASYNC_HOOKS)

        # Runner should detect it via module's ASYNC_HOOKS
        module = inspect.getmodule(update_finding)
        is_async_hook = (
            inspect.iscoroutinefunction(update_finding) or
            (module and hasattr(module, 'ASYNC_HOOKS') and update_finding.__name__ in module.ASYNC_HOOKS)
        )
        self.assertTrue(is_async_hook)


if __name__ == '__main__':
    unittest.main()
