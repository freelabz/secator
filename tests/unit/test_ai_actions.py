# tests/unit/test_ai_actions.py
import unittest

from secator.tasks.ai_actions import ActionContext, dispatch_action


def get_result_text(result):
    """Extract text content from result for comparison."""
    if hasattr(result, 'message'):
        return result.message.lower()
    if hasattr(result, 'content'):
        return result.content.lower()
    return str(result).lower()


class TestActionDispatch(unittest.TestCase):

    def test_dispatch_task_action_dry_run(self):
        action = {
            "action": "task",
            "name": "httpx",
            "targets": ["example.com"],
            "opts": {}
        }
        ctx = ActionContext(
            targets=["example.com"],
            model="gpt-4",
            dry_run=True,
        )

        results = list(dispatch_action(action, ctx))

        # Should yield Info about dry run
        self.assertTrue(len(results) > 0)
        self.assertTrue(any("dry" in get_result_text(r) or "httpx" in get_result_text(r) for r in results))

    def test_dispatch_done_action(self):
        action = {"action": "done", "reason": "completed testing"}
        ctx = ActionContext(
            targets=["example.com"],
            model="gpt-4",
            dry_run=False,
        )

        results = list(dispatch_action(action, ctx))

        self.assertTrue(len(results) > 0)

    def test_dispatch_unknown_action(self):
        action = {"action": "unknown_action"}
        ctx = ActionContext(
            targets=["example.com"],
            model="gpt-4",
        )

        results = list(dispatch_action(action, ctx))

        # Should yield warning about unknown action
        self.assertTrue(any("unknown" in get_result_text(r) for r in results))

    def test_action_context_defaults(self):
        ctx = ActionContext(
            targets=["example.com"],
            model="gpt-4",
        )

        self.assertEqual(ctx.targets, ["example.com"])
        self.assertEqual(ctx.model, "gpt-4")
        self.assertFalse(ctx.dry_run)
        self.assertIsNone(ctx.encryptor)


if __name__ == '__main__':
    unittest.main()
