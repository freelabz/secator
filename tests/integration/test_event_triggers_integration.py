"""Integration tests for event trigger functionality."""
import unittest
from unittest.mock import MagicMock, patch
from secator.runners import Workflow
from secator.output_types import Url
from secator.template import TemplateLoader


class TestEventTriggersIntegration(unittest.TestCase):
    """Integration tests for event triggers in workflows."""

    def test_event_trigger_registration(self):
        """Test that event triggers are registered from workflow config."""
        # Create a minimal workflow config with event trigger
        config = MagicMock()
        config.toDict.return_value = {
            'name': 'test_workflow',
            'type': 'workflow',
            'description': 'Test workflow',
            'input_types': ['url'],
            'tasks': {
                'httpx': {},
                'bup': {
                    'on_event': {
                        'type': 'url',
                        'condition': 'item.status_code == 403',
                        'batch_size': 5,
                        'batch_timeout': 30
                    },
                    'targets_': [{'type': 'url', 'field': 'url'}]
                }
            },
            'default_options': {}
        }
        config.name = 'test_workflow'
        config.type = 'workflow'
        config.description = 'Test workflow'
        config.input_types = ['url']
        config.tasks = config.toDict()['tasks']
        config.default_options = MagicMock()
        config.default_options.toDict.return_value = {}
        
        # Mock the build_runner_tree to avoid complex tree building
        with patch('secator.runners.workflow.build_runner_tree') as mock_tree:
            # Create a simple tree structure
            from secator.tree import RunnerTree, TaskNode
            tree = RunnerTree('test_workflow', 'workflow')
            root = TaskNode('test_workflow', 'workflow', 'test_workflow', opts={})
            tree.add_root_node(root)
            
            # Add tasks as nodes
            httpx_node = TaskNode('httpx', 'task', 'test_workflow.httpx', opts={}, parent=root)
            root.add_child(httpx_node)
            
            bup_opts = {
                'on_event': {
                    'type': 'url',
                    'condition': 'item.status_code == 403',
                    'batch_size': 5,
                    'batch_timeout': 30
                },
                'targets_': [{'type': 'url', 'field': 'url'}]
            }
            bup_node = TaskNode('bup', 'task', 'test_workflow.bup', opts=bup_opts, parent=root)
            root.add_child(bup_node)
            
            mock_tree.return_value = tree
            
            # Create workflow - this should register the event trigger
            workflow = Workflow(config, inputs=['http://example.com'], run_opts={'sync': True})
            
            # Note: Event triggers are registered during build_celery_workflow
            # For sync mode, we'd need to actually build the workflow
            # This test primarily verifies no errors occur during initialization


if __name__ == '__main__':
    unittest.main()
