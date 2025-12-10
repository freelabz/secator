"""Tests for AI generator functionality."""

from unittest.mock import patch

from secator.ai_generator import (
    check_ai_addon,
    get_model_and_key,
    extract_code_block,
)


class TestAIGenerator:
    """Test AI generator functionality."""

    def test_check_ai_addon_installed(self):
        """Test checking if AI addon is installed."""
        # Should be True if litellm is available
        with patch('secator.ai_generator.console'):
            result = check_ai_addon()
            assert result is True

    def test_check_ai_addon_not_installed(self):
        """Test checking if AI addon is not installed."""
        with patch('builtins.__import__', side_effect=ImportError):
            with patch('secator.ai_generator.console') as mock_console:
                result = check_ai_addon()
                assert result is False
                mock_console.print.assert_called_once()

    def test_get_model_and_key_with_config(self):
        """Test getting model and key from config."""
        with patch('secator.ai_generator.CONFIG') as mock_config:
            mock_config.ai.model = 'gpt-4o'
            mock_config.ai.api_key = 'test-key'

            model, api_key = get_model_and_key()

            assert model == 'gpt-4o'
            assert api_key == 'test-key'

    def test_get_model_and_key_with_override(self):
        """Test getting model with override."""
        with patch('secator.ai_generator.CONFIG') as mock_config:
            mock_config.ai.model = 'gpt-4o'
            mock_config.ai.api_key = 'test-key'

            model, api_key = get_model_and_key(model_override='claude-3')

            assert model == 'claude-3'
            assert api_key == 'test-key'

    def test_get_model_and_key_ollama_no_key(self):
        """Test that ollama models don't require API key."""
        with patch('secator.ai_generator.CONFIG') as mock_config:
            mock_config.ai.model = 'ollama/llama3'
            mock_config.ai.api_key = ''

            model, api_key = get_model_and_key()

            assert model == 'ollama/llama3'
            # Should not require API key for ollama
            assert api_key == ''

    def test_get_model_and_key_missing_for_claude(self):
        """Test missing API key for Claude."""
        with patch('secator.ai_generator.CONFIG') as mock_config:
            mock_config.ai.model = 'claude-3-5-sonnet-20241022'
            mock_config.ai.api_key = ''

            with patch('secator.ai_generator.os.environ.get', return_value=''):
                with patch('secator.ai_generator.console'):
                    model, api_key = get_model_and_key()

                    assert model is None
                    assert api_key is None

    def test_extract_code_block_python(self):
        """Test extracting Python code block."""
        content = """Some text
```python
print("Hello World")
```
More text"""

        code = extract_code_block(content, 'python')
        assert code == 'print("Hello World")'

    def test_extract_code_block_yaml(self):
        """Test extracting YAML code block."""
        content = """Some text
```yaml
name: test
type: workflow
```
More text"""

        code = extract_code_block(content, 'yaml')
        assert code == 'name: test\ntype: workflow'

    def test_extract_code_block_no_marker(self):
        """Test extracting code when no markers present."""
        content = "Just plain text"

        code = extract_code_block(content)
        assert code == 'Just plain text'

    def test_extract_code_block_generic(self):
        """Test extracting generic code block."""
        content = """Some text
```
some code here
```
More text"""

        code = extract_code_block(content)
        assert code == 'some code here'
