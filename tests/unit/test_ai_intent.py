# tests/unit/test_ai_intent.py

import unittest
import json


class TestIntentAnalysis(unittest.TestCase):

    def test_parse_intent_response_valid(self):
        from secator.tasks.ai import parse_intent_response

        response = json.dumps({
            "mode": "summarize",
            "queries": [{"_type": "vulnerability"}],
            "reasoning": "User wants a summary"
        })

        result = parse_intent_response(response)

        self.assertEqual(result['mode'], 'summarize')
        self.assertEqual(len(result['queries']), 1)
        self.assertEqual(result['queries'][0]['_type'], 'vulnerability')

    def test_parse_intent_response_with_code_block(self):
        from secator.tasks.ai import parse_intent_response

        response = '''Here's the analysis:
```json
{
    "mode": "attack",
    "queries": [{"_type": "url", "url": {"$contains": "login"}}],
    "reasoning": "User wants to attack login"
}
```
'''

        result = parse_intent_response(response)

        self.assertEqual(result['mode'], 'attack')
        self.assertEqual(result['queries'][0]['_type'], 'url')

    def test_parse_intent_response_invalid(self):
        from secator.tasks.ai import parse_intent_response

        response = "This is not valid JSON"

        result = parse_intent_response(response)

        self.assertIsNone(result)

    def test_get_output_types_schema(self):
        from secator.tasks.ai import get_output_types_schema

        schema = get_output_types_schema()

        self.assertIn('vulnerability', schema)
        self.assertIn('url', schema)
        self.assertIn('port', schema)
        self.assertIn('subdomain', schema)
