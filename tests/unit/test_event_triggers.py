"""Unit tests for event trigger functionality."""
import unittest
from unittest.mock import MagicMock, patch
from secator.runners._base import Runner
from secator.output_types import Url
from secator.template import TemplateLoader


class TestEventTriggers(unittest.TestCase):
    """Test event trigger functionality in Runner."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a minimal config
        config = MagicMock()
        config.toDict.return_value = {
            'name': 'test_runner',
            'type': 'workflow',
            'description': 'Test runner',
            'input_types': [],
            'tasks': {}
        }
        config.name = 'test_runner'
        config.type = 'workflow'
        config.description = 'Test runner'
        config.input_types = []
        
        self.runner = Runner(config, inputs=[], run_opts={'sync': True})

    def test_register_event_trigger(self):
        """Test registering an event trigger."""
        trigger_config = {
            'type': 'url',
            'condition': 'item.status_code == 403',
            'batch_size': 5,
            'batch_timeout': 30,
            'task_name': 'bup',
            'task_opts': {}
        }
        
        self.runner.register_event_trigger('test_trigger', trigger_config)
        
        self.assertIn('test_trigger', self.runner.event_triggers)
        self.assertIn('test_trigger', self.runner.event_batches)
        self.assertEqual(self.runner.event_triggers['test_trigger'], trigger_config)
        self.assertEqual(self.runner.event_batches['test_trigger'], [])

    def test_event_trigger_matching(self):
        """Test that matching items are added to batch."""
        trigger_config = {
            'type': 'url',
            'condition': 'item.status_code == 403',
            'batch_size': 5,
            'batch_timeout': 30,
            'task_name': 'bup',
            'task_opts': {}
        }
        
        self.runner.register_event_trigger('test_trigger', trigger_config)
        
        # Create a matching URL
        url = Url(url='http://example.com', status_code=403)
        self.runner._check_event_triggers(url)
        
        # Check that item was added to batch
        self.assertEqual(len(self.runner.event_batches['test_trigger']), 1)
        self.assertEqual(self.runner.event_batches['test_trigger'][0], url)

    def test_event_trigger_non_matching(self):
        """Test that non-matching items are not added to batch."""
        trigger_config = {
            'type': 'url',
            'condition': 'item.status_code == 403',
            'batch_size': 5,
            'batch_timeout': 30,
            'task_name': 'bup',
            'task_opts': {}
        }
        
        self.runner.register_event_trigger('test_trigger', trigger_config)
        
        # Create a non-matching URL
        url = Url(url='http://example.com', status_code=200)
        self.runner._check_event_triggers(url)
        
        # Check that batch is still empty
        self.assertEqual(len(self.runner.event_batches['test_trigger']), 0)

    def test_event_trigger_batch_full(self):
        """Test that task is triggered when batch is full."""
        trigger_config = {
            'type': 'url',
            'condition': 'item.status_code == 403',
            'batch_size': 2,  # Small batch for testing
            'batch_timeout': 30,
            'task_name': 'bup',
            'task_opts': {}
        }
        
        self.runner.register_event_trigger('test_trigger', trigger_config)
        
        # Add items to fill the batch
        url1 = Url(url='http://example1.com', status_code=403)
        url2 = Url(url='http://example2.com', status_code=403)
        
        self.runner._check_event_triggers(url1)
        self.assertEqual(len(self.runner.event_batches['test_trigger']), 1)
        
        # Adding second item should trigger the task
        self.runner._check_event_triggers(url2)
        
        # Batch should be cleared after triggering
        self.assertEqual(len(self.runner.event_batches['test_trigger']), 0)

    def test_event_lock_lazy_initialization(self):
        """Test that event_lock is lazily initialized."""
        # Initially should be None
        self.assertIsNone(self.runner._event_lock)
        
        # Accessing property should create the lock
        lock = self.runner.event_lock
        self.assertIsNotNone(lock)
        self.assertIsNotNone(self.runner._event_lock)

    def test_cancel_event_timers(self):
        """Test cancelling event timers."""
        trigger_config = {
            'type': 'url',
            'condition': 'item.status_code == 403',
            'batch_size': 10,
            'batch_timeout': 30,
            'task_name': 'bup',
            'task_opts': {}
        }
        
        self.runner.register_event_trigger('test_trigger', trigger_config)
        
        # Add one item to start timer
        url = Url(url='http://example.com', status_code=403)
        self.runner._check_event_triggers(url)
        
        # Timer should be started
        self.assertIn('test_trigger', self.runner.event_timers)
        
        # Cancel timers
        self.runner.cancel_event_timers()
        
        # Timer should be removed
        self.assertEqual(len(self.runner.event_timers), 0)


if __name__ == '__main__':
    unittest.main()
